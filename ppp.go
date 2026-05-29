package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/creack/pty"
)

// RouteCallback is called once pppd establishes the link and reports the
// remote gateway IP and the local interface name (e.g. "ppp0").
type RouteCallback func(gateway, device string)

// PPPSession manages the pppd subprocess, the SSL tunnel, and the data pump
// that bridges them.
type PPPSession struct {
	cfg      *Config
	authKey  string
	tlsCfg   *tls.Config
	callback RouteCallback
}

func NewPPPSession(cfg *Config, authKey string, tlsCfg *tls.Config, cb RouteCallback) *PPPSession {
	return &PPPSession{cfg: cfg, authKey: authKey, tlsCfg: tlsCfg, callback: cb}
}

// Run starts pppd, opens the SSL tunnel, pumps data between them, and blocks
// until pppd exits. Signals are forwarded to pppd.
func (p *PPPSession) Run() error {
	// Open a PTY pair; pppd gets the slave as its stdin/stdout.
	ptm, pts, err := pty.Open()
	if err != nil {
		return fmt.Errorf("pty.Open: %w", err)
	}

	pppArgs := []string{
		"debug", "debug",
		"dump",
		"logfd", "2", // parse device name and remote IP from pppd's log
		"lcp-echo-interval", "10",
		"lcp-echo-failure", "2",
		"ktune",
		"local",
		"noipdefault",
		"noccp", // server is buggy
		"noauth",
		"usepeerdns",
	}

	cmd := exec.Command("pppd", pppArgs...)
	cmd.Stdin = pts
	cmd.Stdout = pts
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		ptm.Close()
		pts.Close()
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		ptm.Close()
		pts.Close()
		return fmt.Errorf("pppd start: %w (are you root?)", err)
	}
	pts.Close() // parent does not need the slave end

	// Connect the SSL tunnel.
	tunnel, err := DialTunnel(p.cfg.Server, p.cfg.Port, p.authKey, p.tlsCfg, p.cfg.MaxLine)
	if err != nil {
		cmd.Process.Kill()
		ptm.Close()
		return fmt.Errorf("tunnel connect: %w", err)
	}

	// Ignore SIGHUP and SIGWINCH for the duration of the session (matches
	// original Python behaviour).
	signal.Ignore(syscall.SIGHUP, syscall.SIGWINCH)
	defer signal.Reset(syscall.SIGHUP, syscall.SIGWINCH)

	// Forward SIGINT/SIGTERM to pppd; kill on second signal.
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)

	sigCount := 0
	go func() {
		for sig := range sigs {
			sigCount++
			if sigCount == 1 {
				slog.Info("caught signal, terminating pppd", "signal", sig)
				cmd.Process.Signal(syscall.SIGTERM)
			} else {
				slog.Info("caught second signal, killing pppd")
				cmd.Process.Signal(syscall.SIGKILL)
			}
		}
	}()

	// Goroutine: tunnel → pty (server PPP data → pppd stdin)
	go func() {
		for {
			packet, err := tunnel.ReadPacket()
			if err != nil {
				slog.Debug("tunnel read ended", "error", err)
				// Signal pppd so it notices the tunnel dropped.
				cmd.Process.Signal(syscall.SIGHUP)
				return
			}
			if len(packet) > 0 {
				ptm.Write(packet)
			}
		}
	}()

	// Goroutine: pty → tunnel (pppd stdout → server)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := ptm.Read(buf)
			if err != nil {
				return
			}
			if err := tunnel.WritePacket(buf[:n]); err != nil {
				slog.Debug("tunnel write ended", "error", err)
				return
			}
		}
	}()

	// Goroutine: parse pppd stderr for device name and remote IP.
	var device string
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "Using interface") {
				fields := strings.Fields(line)
				device = fields[len(fields)-1]
				slog.Info("pppd interface", "device", device)
			}
			if strings.HasPrefix(line, "remote IP address") {
				fields := strings.Fields(line)
				ip := fields[len(fields)-1]
				slog.Info("pppd remote IP", "ip", ip)
				if p.callback != nil {
					p.callback(ip, device)
				}
			}
		}
	}()

	// Block until pppd exits.
	waitErr := cmd.Wait()

	// Close tunnel and PTY master to unblock the data-pump goroutines.
	tunnel.Close()
	ptm.Close()

	slog.Info("shutting down...")

	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			if code == 5 && sigCount > 0 {
				slog.Info("pppd exited cleanly", "code", code)
			} else {
				slog.Error("pppd exited with error", "code", code)
				if code == 2 || code == 3 {
					slog.Warn("are you root? pppd likely needs root privileges")
				}
			}
		}
	}

	return nil
}
