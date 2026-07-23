// file: utils/network.go
package utils

import (
	"net"
	"strings"
)


func GetLocalIPs() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				ips = append(ips, ip.String())
			}
		}
	}
	// Tambahkan loopback manual sebagai perlindungan ekstra
	ips = append(ips, "127.0.0.1", "::1")
	return ips
}

// CheckIPType mengembalikan "4" untuk IPv4, "6" untuk IPv6, dan "" jika invalid
func CheckIPType(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	
	// Support CIDR parsing
	ip, _, err := net.ParseCIDR(ipStr)
	if err != nil {
		ip = net.ParseIP(ipStr)
	}

	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "4"
	}
	return "6"
}