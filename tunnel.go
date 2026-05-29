package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// Tunnel is a raw TLS connection to the VPN server speaking the SonicWALL
// PPP-over-SSL framing protocol: each PPP packet is preceded by a 4-byte
// big-endian length.
type Tunnel struct {
	conn    net.Conn
	reader  *bufio.Reader
	maxLine int
}

// MakeTLSConfig returns a tls.Config appropriate for cfg.
// When a fingerprint is set, CA verification is disabled and the fingerprint
// is verified instead. Otherwise, standard CA verification is used.
func MakeTLSConfig(cfg *Config) (*tls.Config, error) {
	if cfg.Fingerprint == "" {
		return nil, nil // nil = use Go's default (CA verification)
	}

	// Normalise fingerprint to lowercase hex without colons for comparison.
	expected := strings.ToLower(strings.ReplaceAll(cfg.Fingerprint, ":", ""))

	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("server presented no certificate")
			}
			sum := sha1.Sum(cs.PeerCertificates[0].Raw)
			actual := fmt.Sprintf("%x", sum)
			if actual != expected {
				return fmt.Errorf("certificate fingerprint mismatch:\n  got:  %s\n  want: %s",
					formatFingerprint(sum[:]), cfg.Fingerprint)
			}
			return nil
		},
	}, nil
}

// formatFingerprint formats a raw byte slice as colon-separated hex pairs.
func formatFingerprint(raw []byte) string {
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// DialTunnel opens a TLS connection to host:port, sends the SonicWALL
// CONNECT-style tunnel handshake headers, then returns a ready Tunnel.
func DialTunnel(host string, port int, sessionID string, tlsCfg *tls.Config, maxLine int) (*Tunnel, error) {
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("TLS dial: %w", err)
	}

	headers := []string{
		"CONNECT localhost:0 HTTP/1.0",
		"X-SSLVPN-PROTOCOL: 2.0",
		"X-SSLVPN-SERVICE: NETEXTENDER",
		"Proxy-Authorization: " + sessionID,
		"X-NX-Client-Platform: Linux",
		"Connection-Medium: MacOS",
		"X-NE-PROTOCOL: 2.0",
		"Frame-Encode: off",
	}
	// The server expects: first-line\r\n then header lines joined by \r\n, then \r\n\r\n
	request := strings.Join(headers, "\r\n") + "\r\n\r\n"

	if _, err := conn.Write([]byte(request)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tunnel handshake: %w", err)
	}

	return &Tunnel{
		conn:    conn,
		reader:  bufio.NewReaderSize(conn, 65536),
		maxLine: maxLine,
	}, nil
}

// ReadPacket reads one framed PPP packet from the tunnel.
// On the very first call it also detects an HTTP error response from the server.
func (t *Tunnel) ReadPacket() ([]byte, error) {
	// Peek at the first 4 bytes: if the server rejected the handshake it sends
	// an HTTP error line starting with "HTTP".
	peek, err := t.reader.Peek(4)
	if err != nil {
		return nil, err
	}
	if string(peek) == "HTTP" {
		line, _ := t.reader.ReadString('\n')
		return nil, fmt.Errorf("server rejected tunnel: %s", strings.TrimSpace(line))
	}

	var header [4]byte
	if _, err := io.ReadFull(t.reader, header[:]); err != nil {
		return nil, err
	}

	plen := binary.BigEndian.Uint32(header[:])
	if plen == 0 {
		return nil, nil
	}

	packet := make([]byte, plen)
	_, err = io.ReadFull(t.reader, packet)
	return packet, err
}

// WritePacket sends data to the tunnel as one or more framed packets, each at
// most maxLine bytes long.
func (t *Tunnel) WritePacket(data []byte) error {
	for len(data) > 0 {
		n := len(data)
		if n > t.maxLine {
			n = t.maxLine
		}

		frame := make([]byte, 4+n)
		binary.BigEndian.PutUint32(frame[:4], uint32(n))
		copy(frame[4:], data[:n])

		if _, err := t.conn.Write(frame); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// Close closes the underlying TLS connection.
func (t *Tunnel) Close() {
	t.conn.Close()
}

// PrintServerFingerprint connects to host:443, skips CA verification, and
// prints the SHA-1 fingerprint of the server's leaf certificate.
func PrintServerFingerprint(host string, port int) {
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not connect to print fingerprint: %v\n", err)
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		fmt.Fprintln(os.Stderr, "server presented no certificates")
		return
	}

	sum := sha1.Sum(certs[0].Raw)
	fmt.Printf("server certificate fingerprint: %s\n", formatFingerprint(sum[:]))
}
