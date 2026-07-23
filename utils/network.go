// file: utils/network.go
package utils

import (
	"net"
	"strings"
)

// ==============================================================================
// 1. ANTI-LOCKOUT: LOCAL IP DETECTOR
// ==============================================================================

// GetLocalIPs memindai lapisan perangkat keras jaringan server secara langsung.
// Menarik semua IP (v4 & v6) yang sedang aktif untuk dimasukkan ke dalam Whitelist RAM.
func GetLocalIPs() []string {
	var ips []string
	
	// Peta (Hash Map) untuk mencegah IP ganda/duplikat masuk ke IPSet
	uniqueIPs := make(map[string]bool)

	ifaces, err := net.Interfaces()
	if err != nil {
		// FALLBACK ABSOLUT: Jika kernel OS gagal merespons, amankan Loopback
		LogError("Failed to read hardware network interfaces: %v", err)
		return []string{"127.0.0.1", "::1"}
	}

	for _, i := range ifaces {
		// OPTIMASI MEMORI: Abaikan interface jaringan yang sedang tidak aktif (DOWN)
		if i.Flags&net.FlagUp == 0 {
			continue
		}

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
				// PRUNING KETAT: Abaikan IPv6 Multicast & Link-Local (fe80::)
				// IP jenis ini tidak bisa di-routing ke internet, memasukkannya ke firewall
				// publik hanya akan membuang memori dan menimbulkan risiko spoofing.
				if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
					continue
				}

				ipStr := ip.String()
				if !uniqueIPs[ipStr] {
					uniqueIPs[ipStr] = true
					ips = append(ips, ipStr)
				}
			}
		}
	}

	// PASTIKAN: Localhost/Loopback selalu masuk ke whitelist apa pun yang terjadi,
	// untuk menjamin komunikasi internal (MySQL, Nginx ke PHP-FPM, Redis) tidak terblokir.
	if !uniqueIPs["127.0.0.1"] { ips = append(ips, "127.0.0.1") }
	if !uniqueIPs["::1"] { ips = append(ips, "::1") }

	return ips
}

// ==============================================================================
// 2. NETWORK DATA VALIDATOR
// ==============================================================================

// CheckIPType membedah format IP yang diberikan Admin/Log dengan presisi tinggi.
// Mengembalikan "4" untuk IPv4, "6" untuk IPv6, dan string kosong "" jika invalid/hacker payload.
func CheckIPType(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return ""
	}

	// Skenario 1: Input berupa CIDR Range (Contoh: 192.168.1.0/24)
	if strings.Contains(ipStr, "/") {
		ip, _, err := net.ParseCIDR(ipStr)
		if err != nil {
			return "" // Tolak jika format subnet mask rusak (Contoh: 10.0.0.0/999)
		}
		
		// Deteksi Versi
		if ip.To4() != nil {
			return "4"
		}
		if ip.To16() != nil {
			return "6"
		}
		return ""
	}

	// Skenario 2: Input berupa IP Tunggal (Contoh: 8.8.8.8)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "" // Tolak jika bukan IP Asli (Contoh: "localhost", "1.2.3")
	}
	
	// Catatan Arsitektur Go:
	// Pengecekan To4() HARUS didahulukan dari To16(), karena di dalam net library Go,
	// IPv4 juga merupakan format yang valid jika diekspansi ke dalam blok IPv6 memori (IPv4-mapped IPv6).
	if ip.To4() != nil {
		return "4"
	}
	if ip.To16() != nil {
		return "6"
	}
	
	return ""
}
