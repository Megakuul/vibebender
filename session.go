package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
)

// NXSession manages the full lifecycle of a NetExtender VPN session:
// HTTP authentication, session negotiation, tunnel setup, and routing.
type NXSession struct {
	cfg        *Config
	tlsCfg     *tls.Config
	client     *http.Client
	dns        DNSManager
	srvOptions map[string]string
	routes     []string
	device     string
}

func NewNXSession(cfg *Config) *NXSession {
	return &NXSession{cfg: cfg}
}

func (s *NXSession) Run() error {
	tlsCfg, err := MakeTLSConfig(s.cfg)
	if err != nil {
		return err
	}
	s.tlsCfg = tlsCfg
	s.dns = NewDNSManager(s.cfg.DNSBackend)

	jar, _ := cookiejar.New(nil)
	s.client = &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	slog.Info("logging in...")
	if err := s.login(s.cfg.Username, s.cfg.Password, s.cfg.Domain, nil); err != nil {
		return err
	}
	defer s.logout()

	slog.Info("starting session...")
	if err := s.startSession(); err != nil {
		return err
	}

	slog.Info("dialing tunnel...")
	return s.tunnel()
}

func (s *NXSession) baseURL() string {
	return fmt.Sprintf("https://%s:%d", s.cfg.Server, s.cfg.Port)
}

// login authenticates with the server, handling RADIUS challenge and MFA/OTP
// two-factor flows as needed. extra contains additional POST fields for 2FA retries.
func (s *NXSession) login(username, password, domain string, extra map[string]string) error {
	form := url.Values{
		"username": {username},
		"password": {password},
		"domain":   {domain},
		"login":    {"true"},
	}
	for k, v := range extra {
		form.Set(k, v)
	}

	req, err := http.NewRequest("POST", s.baseURL()+"/cgi-bin/userLogin", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-NE-SESSIONPROMPT", "true")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	message := neMessage(resp)
	twoFactor := resp.Header.Get("X-NE-tf")

	switch twoFactor {
	case "5": // RADIUS challenge – re-login with the user's response
		slog.Info("2FA required (RADIUS challenge)")
		response, err := promptForResponse(s.cfg, message)
		if err != nil {
			return fmt.Errorf("2FA prompt: %w", err)
		}
		return s.login(username, password, domain, map[string]string{
			"pstate":      resp.Header.Get("X-NE-rsastate"),
			"state":       "RADIUSCHALLENGE",
			"radiusReply": response,
		})

	case "1": // MFA / OTP – post to a separate endpoint
		slog.Info("MFA required (OTP)")
		response, err := promptForResponse(s.cfg, message)
		if err != nil {
			return fmt.Errorf("MFA prompt: %w", err)
		}

		// Carry the swap cookie manually as Python does.
		swapVal := ""
		for _, c := range resp.Cookies() {
			if c.Name == "swap" {
				swapVal = c.Value
				break
			}
		}

		otpReq, err := http.NewRequest("POST", s.baseURL()+"/cgi-bin/otpLogin",
			strings.NewReader(url.Values{"password": {response}}.Encode()))
		if err != nil {
			return err
		}
		otpReq.Header.Set("User-Agent", userAgent)
		otpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		otpReq.Header.Set("X-NE-pda", "true")
		otpReq.AddCookie(&http.Cookie{Name: "swap", Value: swapVal})

		otpResp, err := s.client.Do(otpReq)
		if err != nil {
			return fmt.Errorf("OTP request: %w", err)
		}
		defer otpResp.Body.Close()
		io.Copy(io.Discard, otpResp.Body)

		message = neMessage(otpResp)
		twoFactor = otpResp.Header.Get("X-NE-tf")
	}

	if twoFactor != "" && twoFactor != "0" {
		return fmt.Errorf("server requested unsupported 2FA method %q", twoFactor)
	}
	if message != "" {
		return fmt.Errorf("server error: %s", message)
	}
	return nil
}

func (s *NXSession) logout() {
	req, err := http.NewRequest("GET", s.baseURL()+"/cgi-bin/userLogout", nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// startSession calls /cgi-bin/sslvpnclient to retrieve server options and routes.
func (s *NXSession) startSession() error {
	req, err := http.NewRequest("GET", s.baseURL()+"/cgi-bin/sslvpnclient", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	q := req.URL.Query()
	q.Set("launchplatform", "mac")
	q.Set("neProto", "3")
	q.Set("supportipv6", "no")
	req.URL.RawQuery = q.Encode()

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("session start request: %w", err)
	}
	defer resp.Body.Close()

	if msg := neMessage(resp); msg != "" {
		return fmt.Errorf("server error: %s", msg)
	}

	srvOptions := make(map[string]string)
	var routes []string

	// The response is HTML with key=value lines mixed in; skip anything HTML-like.
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "<") || strings.HasPrefix(line, "}<") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			slog.Debug("unexpected session line", "line", line)
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		slog.Debug("server option", "key", key, "value", val)

		if key == "Route" {
			routes = append(routes, val)
		} else if _, exists := srvOptions[key]; !exists {
			srvOptions[key] = val
		} else {
			slog.Info("duplicate server option", "key", key)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	s.srvOptions = srvOptions
	s.routes = routes
	return nil
}

func (s *NXSession) tunnel() error {
	// Determine auth key based on protocol version the server reported.
	var authKey string
	switch ver := s.srvOptions["NX_TUNNEL_PROTO_VER"]; ver {
	case "":
		// Legacy: use the swap session cookie.
		u, _ := url.Parse(s.baseURL())
		for _, c := range s.client.Jar.Cookies(u) {
			if c.Name == "swap" {
				authKey = c.Value
				break
			}
		}
	case "2.0":
		authKey = s.srvOptions["SessionId"]
	default:
		slog.Warn("unknown tunnel version, falling back to SessionId", "version", ver)
		authKey = s.srvOptions["SessionId"]
	}

	pppSess := NewPPPSession(s.cfg, authKey, s.tlsCfg, s.postConnect)
	if err := pppSess.Run(); err != nil {
		return err
	}

	// Clean up DNS after pppd exits.
	if s.dns != nil && s.device != "" {
		if err := s.dns.Remove(s.device); err != nil {
			slog.Warn("DNS removal failed", "error", err)
		}
	}
	return nil
}

// postConnect is called by PPPSession once pppd establishes the link and
// reports the remote gateway address and local interface name.
func (s *NXSession) postConnect(gateway, device string) {
	s.device = device
	s.setupRoutes(gateway)
	if s.dns != nil {
		servers := serversFromOptions(s.srvOptions)
		if err := s.dns.Set(device, servers, s.srvOptions["dnsSuffix"]); err != nil {
			slog.Warn("DNS setup failed", "error", err)
		}
	}
}

// setupRoutes adds kernel routing table entries for all routes received from
// the server, pointing through the PPP gateway.
func (s *NXSession) setupRoutes(gateway string) {
	gw := net.ParseIP(gateway)
	seen := make(map[string]bool)

	for _, route := range s.routes {
		if seen[route] {
			continue
		}
		seen[route] = true

		dst, err := parseRoute(route)
		if err != nil {
			slog.Warn("invalid route from server", "route", route, "error", err)
			continue
		}

		if err := addRoute(dst, gw); err != nil {
			slog.Warn("failed to add route", "route", route, "error", err)
		}
	}
	slog.Info("remote routing configured, VPN is up")
}

// neMessage extracts the X-NE-Message header (case-insensitive) from a response.
func neMessage(resp *http.Response) string {
	if v := resp.Header.Get("X-NE-Message"); v != "" {
		return v
	}
	return resp.Header.Get("X-NE-message")
}

// promptForResponse prints prompt to stderr and reads a line from stdin.
func promptForResponse(_ *Config, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, strings.TrimSpace(prompt)+" ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}
