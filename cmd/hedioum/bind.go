package main

import (
	"fmt"
	"net"
)

// isLoopbackBind reports whether a listener bind address is loopback-only.
func isLoopbackBind(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

// validBind accepts "" (all interfaces) or an IP literal.
func validBind(addr string) error {
	if addr == "" || net.ParseIP(addr) != nil {
		return nil
	}
	return fmt.Errorf("%q is not an IP address", addr)
}
