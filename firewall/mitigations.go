// file: firewall/mitigations.go
package firewall

import (
	"bytes"
	"strings"
	"os/user"
	"raf/config"
	"raf/utils"
)

// AppendAdvancedMitigations merakit rules iptables untuk proteksi Layer 4 (Anti-DDoS) & SMTP Egress
func AppendAdvancedMitigations(buffer *bytes.Buffer, isIPv6 bool) {
	config.CoreData.Mutex.RLock()
	defer config.CoreData.Mutex.RUnlock()

	packetFilter := config.CoreData.Config["RAF_PACKET_FILTER"]
	synFlood     := config.CoreData.Config["RAF_SYNFLOOD"]
	connLimit    := config.CoreData.Config["RAF_CONNLIMIT"]
	portFlood    := config.CoreData.Config["RAF_PORTFLOOD"]
	smtpBlock    := config.CoreData.Config["RAF_SMTP_BLOCK"]

	hasMitigation := false

	// 1. INVALID PACKETS & STEALTH SCAN FILTER
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

	// 2. SYN FLOOD PROTECTION
	if synFlood == "1" {
		rate := config.CoreData.Config["RAF_SYNFLOOD_RATE"]
		burst := config.CoreData.Config["RAF_SYNFLOOD_BURST"]
		if rate == "" { rate = "100/s" }
		if burst == "" { burst = "150" }
		buffer.WriteString("-A RAF_ADVANCED -p tcp --syn -m limit --limit " + rate + " --limit-burst " + burst + " -j RETURN\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --syn -j DROP\n")
		hasMitigation = true
	}

	// 3. CONNECTION LIMITING
	if connLimit != "" {
		for _, rule := range strings.Split(connLimit, ",") {
			parts := strings.Split(strings.TrimSpace(rule), ";")
			if len(parts) == 2 {
				buffer.WriteString("-A RAF_ADVANCED -p tcp --syn --dport " + parts[0] + " -m connlimit --connlimit-above " + parts[1] + " -j DROP\n")
			}
		}
		hasMitigation = true
	}

	// 4. PORT FLOODING PROTECTION
	if portFlood != "" {
		for _, rule := range strings.Split(portFlood, ",") {
			parts := strings.Split(strings.TrimSpace(rule), ";")
			if len(parts) == 4 {
				name := "RAF_PF_" + parts[0]
				buffer.WriteString("-A RAF_ADVANCED -p " + parts[1] + " --dport " + parts[0] + " -m state --state NEW -m recent --set --name " + name + "\n")
				buffer.WriteString("-A RAF_ADVANCED -p " + parts[1] + " --dport " + parts[0] + " -m state --state NEW -m recent --update --seconds " + parts[3] + " --hitcount " + parts[2] + " --name " + name + " -j DROP\n")
			}
		}
		hasMitigation = true
	}

	// SINKRONISASI: 5. SMTP EGRESS BLOCK (Spam Protection)
	if smtpBlock == "1" {
		smtpPorts := config.CoreData.Config["RAF_SMTP_PORTS"]
		smtpUsers := config.CoreData.Config["RAF_SMTP_ALLOWUSER"]
		if smtpPorts == "" { smtpPorts = "25,465,587" }

		for _, port := range strings.Split(smtpPorts, ",") {
			port = strings.TrimSpace(port)
			if port == "" { continue }

			// Izinkan Sistem Users (Uid Owner)
			for _, u := range strings.Split(smtpUsers, ",") {
				u = strings.TrimSpace(u)
				if u == "" { continue }
				usr, err := user.Lookup(u)
				if err == nil {
					buffer.WriteString("-A RAF_OUTPUT -p tcp --dport " + port + " -m owner --uid-owner " + usr.Uid + " -j ACCEPT\n")
				}
			}
			// Pastikan root UID 0 selalu diizinkan
			buffer.WriteString("-A RAF_OUTPUT -p tcp --dport " + port + " -m owner --uid-owner 0 -j ACCEPT\n")
			// Drop selain yang di atas (Script PHP yang coba Bypass)
			buffer.WriteString("-A RAF_OUTPUT -p tcp --dport " + port + " -j DROP\n")
		}
		hasMitigation = true
	}

	if hasMitigation && !isIPv6 {
		utils.LogInfo("RAF L4 Advanced Mitigations & SMTP Filters generated.")
	}
}
