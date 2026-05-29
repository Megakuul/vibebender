package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
)

// parseRoute parses a route in either standard CIDR ("10.0.0.0/24") or
// network/netmask ("10.0.0.0/255.255.255.0") notation.
// The SonicWALL server sends the latter format.
func parseRoute(route string) (*net.IPNet, error) {
	// Fast path: standard CIDR notation already works.
	if _, ipNet, err := net.ParseCIDR(route); err == nil {
		return ipNet, nil
	}

	// Dotted-decimal netmask: split on "/" and parse each half.
	parts := strings.SplitN(route, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("unrecognised route format %q", route)
	}

	ip := net.ParseIP(parts[0]).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid IP in route %q", route)
	}

	maskIP := net.ParseIP(parts[1]).To4()
	if maskIP == nil {
		return nil, fmt.Errorf("invalid netmask in route %q", route)
	}

	mask := net.IPMask(maskIP)
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil
}

// addRoute adds a kernel routing table entry for dst via gw.
func addRoute(dst *net.IPNet, gw net.IP) error {
	return netlink.RouteAdd(&netlink.Route{
		Dst: dst,
		Gw:  gw,
	})
}
