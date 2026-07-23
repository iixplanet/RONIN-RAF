// file: firewall/mitigations.go
package firewall

import (
	"bytes"
	"os/user"
	"strings"
	"raf/config"
	"raf/utils"
)

// AppendAdvancedMitigations merakit rules iptables untuk proteksi Anti-DDoS, Portflood, dan SMTP Egress
func AppendAdvancedMitigations(buffer *bytes.Buffer, isIPv6 bool) {
	config.CoreData.Mutex.RLock()
	defer config.CoreData.Mutex.RUnlock()

	packetFilter := config.CoreData.Config["RAF_PACKET_FILTER"]
	synFlood     := config.CoreData.Config["RAF_SYNFLOOD"]
	synRate      := config.CoreData.Config["RAF_SYNFLOOD_RATE"]
	synBurst     := config.CoreData.Config["RAF_SYNFLOOD_BURST"]
	connLimit    := config.CoreData.Config["RAF_CONNLIMIT"]
	portFlood    := config.CoreData.Config["RAF_PORTFLOOD"]
	
	smtpBlock        := config.CoreData.Config["RAF_SMTP_BLOCK"]
	smtpPorts        := config.CoreData.Config["RAF_SMTP_PORTS"]
	smtpUsers        := config.CoreData.Config["RAF_SMTP_ALLOWUSER"]
	smtpAuthRestrict := config.CoreData.Config["RAF_SMTPAUTH_RESTRICT"]

	hasMitigation := false

	// ==============================================================================
	// 1. INVALID PACKETS & STEALTH SCAN FILTER (XMAS, NULL, FIN SCAN)
	// ==============================================================================
	if packetFilter == "1" {
		// Drop paket dengan state rusak/invalid secara sepihak
		buffer.WriteString("-A RAF_ADVANCED -m state --state INVALID -j DROP\n")
		// Drop stealth scans yang sering digunakan oleh Nmap/Zmap
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags ALL NONE -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags ALL ALL -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags SYN,RST SYN,RST -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags FIN,RST FIN,RST -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags ACK,FIN FIN -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags ACK,PSH PSH -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --tcp-flags ACK,URG URG -j DROP\n")
		
		// Aturan Emas: Setiap koneksi TCP BARU (NEW) wajib diawali dengan flag SYN!
		buffer.WriteString("-A RAF_ADVANCED -p tcp -m state --state NEW ! --syn -j DROP\n")
		
		hasMitigation = true
	}

	// ==============================================================================
	// 2. SYN FLOOD PROTECTION (DDoS MITIGATION)
	// ==============================================================================
	if synFlood == "1" {
		if synRate == "" { synRate = "100/s" }
		if synBurst == "" { synBurst = "150" }

		// Konsep Limitasi Kernel:
		// Jika request masuk masih di bawah limit (Contoh: 100/sec), maka lewati (RETURN) ke proses normal
		buffer.WriteString("-A RAF_ADVANCED -p tcp --syn -m limit --limit " + synRate + " --limit-burst " + synBurst + " -j RETURN\n")
		// Jika meluap melebihi limit di atas, hancurkan seketika!
		buffer.WriteString("-A RAF_ADVANCED -p tcp --syn -j DROP\n")
		
		hasMitigation = true
	}

	// ==============================================================================
	// 3. CONNECTION LIMITING (CONNLIMIT)
	// ==============================================================================
	// Mencegah serangan koneksi masif (seperti Slowloris) ke port spesifik
	// Format Config: port;limit,port;limit (Contoh: 22;5,80;20)
	if connLimit != "" {
		for _, rule := range strings.Split(connLimit, ",") {
			parts := strings.Split(strings.TrimSpace(rule), ";")
			if len(parts) == 2 {
				port := strings.TrimSpace(parts[0])
				limit := strings.TrimSpace(parts[1])
				
				if port != "" && limit != "" {
					buffer.WriteString("-A RAF_ADVANCED -p tcp --syn --dport " + port + " -m connlimit --connlimit-above " + limit + " -j DROP\n")
				}
			}
		}
		hasMitigation = true
	}

	// ==============================================================================
	// 4. PORT FLOODING PROTECTION (RECENT MODULE)
	// ==============================================================================
	// Membatasi koneksi "BARU" dalam kurun waktu tertentu. Sangat ampuh mencegah Brute-Force Botnet terdistribusi.
	// Format Config: port;protocol;hitcount;seconds (Contoh: 22;tcp;5;300 -> Max 5 koneksi per 5 menit)
	if portFlood != "" {
		for _, rule := range strings.Split(portFlood, ",") {
			parts := strings.Split(strings.TrimSpace(rule), ";")
			if len(parts) == 4 {
				port := strings.TrimSpace(parts[0])
				proto := strings.TrimSpace(parts[1])
				hit := strings.TrimSpace(parts[2])
				sec := strings.TrimSpace(parts[3])

				if port != "" && proto != "" && hit != "" && sec != "" {
					name := "RAF_PF_" + port // Nama memori tracker internal
					// Catat IP yang mencoba koneksi baru ke port ini
					buffer.WriteString("-A RAF_ADVANCED -p " + proto + " --dport " + port + " -m state --state NEW -m recent --set --name " + name + "\n")
					// Drop jika akumulasi hit melebihi batas waktu (seconds)
					buffer.WriteString("-A RAF_ADVANCED -p " + proto + " --dport " + port + " -m state --state NEW -m recent --update --seconds " + sec + " --hitcount " + hit + " --name " + name + " -j DROP\n")
				}
			}
		}
		hasMitigation = true
	}

	// ==============================================================================
	// 5. SMTP AUTH RESTRICTION (ANTI CREDENTIAL STUFFING)
	// ==============================================================================
	// Jika fitur ini menyala, autentikasi SMTP (port 465, 587) HANYA BISA DIAKSES oleh Localhost 
	// dan IP Whitelist (RAF_ALLOW). Hacker dari luar akan langsung mendapatkan 'Connection Refused'.
	if smtpAuthRestrict == "1" {
		// Logika: Karena rule `RAF_ALLOW` dan Loopback (`lo`) dijalankan SEBELUM `RAF_ADVANCED`, 
		// maka memblokir port ini di sini adalah langkah arsitektural yang jenius!
		buffer.WriteString("-A RAF_ADVANCED -p tcp --dport 465 -j DROP\n")
		buffer.WriteString("-A RAF_ADVANCED -p tcp --dport 587 -j DROP\n")
		hasMitigation = true
	}

	// ==============================================================================
	// 6. SMTP EGRESS BLOCK (ANTI-SPAM OUTBOUND)
	// ==============================================================================
	// Melarang script PHP bajakan (Webshell) mengirim email Spam ke luar server.
	// Hanya user sistem sah (root, exim, mailman) yang diizinkan menggunakan port SMTP keluar.
	if smtpBlock == "1" {
		if smtpPorts == "" { smtpPorts = "25,465,587" }
		if smtpUsers == "" { smtpUsers = "root,exim,postfix,mail,mailman" }

		for _, port := range strings.Split(smtpPorts, ",") {
			port = strings.TrimSpace(port)
			if port == "" { continue }

			// A) Selalu izinkan akun ROOT (UID 0) untuk komunikasi keluar
			buffer.WriteString("-A RAF_OUTPUT -p tcp --dport " + port + " -m owner --uid-owner 0 -j ACCEPT\n")

			// B) Resolusi User OS Linux menjadi UID, lalu izinkan
			for _, u := range strings.Split(smtpUsers, ",") {
				u = strings.TrimSpace(u)
				if u == "" || u == "root" { continue }

				usr, err := user.Lookup(u)
				if err == nil {
					buffer.WriteString("-A RAF_OUTPUT -p tcp --dport " + port + " -m owner --uid-owner " + usr.Uid + " -j ACCEPT\n")
				}
			}

			// C) DROP SEMUA KONEKSI SMTP SELAIN USER DI ATAS!
			buffer.WriteString("-A RAF_OUTPUT -p tcp --dport " + port + " -j DROP\n")
		}
		hasMitigation = true
	}

	// Cetak log sekali saja saat fungsi dieksekusi untuk IPv4 agar terminal tidak spam
	if hasMitigation && !isIPv6 {
		utils.LogInfo("L4 Advanced Mitigations (Anti-DDoS, SYN, SMTP Filters) fully generated.")
	}
}
