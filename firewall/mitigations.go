// file: firewall/mitigations.go
package firewall

import (
	"bytes"
	"strings"
	"raf/config"
	"raf/utils"
)

// AppendAdvancedMitigations merakit rules iptables untuk proteksi Layer 4 (Anti-DDoS)
func AppendAdvancedMitigations(buffer *bytes.Buffer, isIPv6 bool) {
	config.CoreData.Mutex.RLock()
	defer config.CoreData.Mutex.RUnlock()

	packetFilter := config.CoreData.Config["RAF_PACKET_FILTER"]
	synFlood     := config.CoreData.Config["RAF_SYNFLOOD"]
	connLimit    := config.CoreData.Config["RAF_CONNLIMIT"]
	portFlood    := config.CoreData.Config["RAF_PORTFLOOD"]

	hasMitigation := false

	// ========================================================
	// 1. INVALID PACKETS & STEALTH SCAN FILTER
	// ========================================================
	// Menggagalkan teknik scanning nmap tersembunyi (XMAS, NULL, FIN scan)
	if packetFilter == "1" {
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags ALL NONE -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags ALL ALL -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags SYN,RST SYN,RST -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags FIN,RST FIN,RST -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags ACK,FIN FIN -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags ACK,PSH PSH -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags ACK,URG URG -j DROP\n")
		hasMitigation = true
	}

	// ========================================================
	// 2. SYN FLOOD PROTECTION (TCP)
	// ========================================================
	if synFlood == "1" {
		rate := config.CoreData.Config["RAF_SYNFLOOD_RATE"]
		burst := config.CoreData.Config["RAF_SYNFLOOD_BURST"]
		if rate == "" { rate = "100/s" }
		if burst == "" { burst = "150" }

		// Jika traffic SYN masih dalam batas limit, lewati (RETURN ke chain utama)
		buffer.WriteString("-A RAF_ADVANCED -p tcp --syn -m limit --limit " + rate + " --limit-burst " + burst + " -j RETURN\n")
		// Jika melebihi limit, DROP paksa (Mitigasi DDoS)
		buffer.WriteString("-A RAF_ADVANCED -p tcp --syn -j DROP\n")
		hasMitigation = true
	}

	// ========================================================
	// 3. CONNECTION LIMITING (CONNLIMIT)
	// ========================================================
	// Format: port;limit,port;limit (e.g., 22;5,80;20)
	if connLimit != "" {
		rules := strings.Split(connLimit, ",")
		for _, rule := range rules {
			parts := strings.Split(strings.TrimSpace(rule), ";")
			if len(parts) == 2 {
				port := parts[0]
				limit := parts[1]
				buffer.WriteString("-A RAF_ADVANCED -p tcp --syn --dport " + port + " -m connlimit --connlimit-above " + limit + " -j DROP\n")
			}
		}
		hasMitigation = true
	}

	// ========================================================
	// 4. PORT FLOODING PROTECTION (RECENT)
	// ========================================================
	// Melindungi dari brute-force botnet terdistribusi
	// Format: port;protocol;hitcount;seconds (e.g., 22;tcp;5;300)
	if portFlood != "" {
		rules := strings.Split(portFlood, ",")
		for _, rule := range rules {
			parts := strings.Split(strings.TrimSpace(rule), ";")
			if len(parts) == 4 {
				port, proto, hitcount, seconds := parts[0], parts[1], parts[2], parts[3]
				// Nama set tracker memori kernel
				name := "RAF_PF_" + port

				// Daftarkan koneksi baru ke dalam list tracker
				buffer.WriteString("-A RAF_ADVANCED -p " + proto + " --dport " + port + " -m state --state NEW -m recent --set --name " + name + "\n")
				// Periksa apakah IP ini melewati limit dalam kurun waktu sekian detik, jika ya = DROP
				buffer.WriteString("-A RAF_ADVANCED -p " + proto + " --dport " + port + " -m state --state NEW -m recent --update --seconds " + seconds + " --hitcount " + hitcount + " --name " + name + " -j DROP\n")
			}
		}
		hasMitigation = true
	}

	if hasMitigation && !isIPv6 {
		utils.LogInfo("L4 Advanced Mitigations (Anti-DDoS, SYN, Stealth) generated.")
	}
}