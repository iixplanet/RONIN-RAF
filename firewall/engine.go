// file: firewall/engine.go
package firewall

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"raf/config"
	"raf/intelligence"
	"raf/utils"
)

// ==============================================================================
// 1. ANTI-LOCKOUT PARSERS (SISTEM KEKEBALAN ADMIN)
// ==============================================================================

// getSSHPort membaca port SSH yang sebenarnya sedang dipakai dari konfigurasi OS Linux.
func getSSHPort() string {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			// Hanya ambil yang tidak di-comment
			if strings.HasPrefix(line, "Port ") && !strings.HasPrefix(line, "#") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Port "))
			}
		}
	}
	return "22" // Default Fallback
}

// getRoninPort memastikan port UI Dashboard Firewall kita tidak pernah terkunci
func getRoninPort() string {
	data, err := os.ReadFile("/usr/local/ronin/config.ronin")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "listen_port") && !strings.HasPrefix(line, "#") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					return strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				}
			}
		}
	}
	return "5029" // Default Fallback
}

// appendUnique menyatukan port manual dan port otomatis tanpa duplikasi
func appendUnique(slice []string, items ...string) []string {
	m := make(map[string]bool)
	for _, v := range slice { m[strings.TrimSpace(v)] = true }
	
	var res []string
	for _, v := range slice { res = append(res, strings.TrimSpace(v)) }
	
	for _, item := range items {
		item = strings.TrimSpace(item)
		if !m[item] && item != "" {
			res = append(res, item)
			m[item] = true
		}
	}
	return res
}

// ==============================================================================
// 2. KERNEL FIREWALL ORCHESTRATOR
// ==============================================================================

// removeMainHooks mencabut kait (hook) dari OS Utama agar tidak terjadi duplikasi saat Reload
func removeMainHooks(bin string) {
	// Flag -w berguna mencegah error "xtables lock" jika berbenturan dengan Docker
	exec.Command(bin, "-w", "-D", "INPUT", "-j", "RAF_INPUT").Run()
	exec.Command(bin, "-w", "-D", "OUTPUT", "-j", "RAF_OUTPUT").Run()
}

// ApplyIptables adalah Trigger Master untuk membangun ulang seluruh struktur Firewall
func ApplyIptables() {
	// 1. Sinkronisasi Memori IPSet terlebih dahulu
	if err := RebuildIPSets(); err != nil {
		utils.LogWarn("IPSet build encountered issues. Firewall might operate in degraded mode.")
	}

	config.CoreData.Mutex.RLock()
	defer config.CoreData.Mutex.RUnlock()

	utils.LogInfo("Building Stateful Packet Inspection (SPI) Rules...")

	// 2. Cabut hook OS yang lama (jika sedang reload)
	removeMainHooks("iptables")
	if config.CoreData.Config["RAF_IPV6"] == "1" {
		removeMainHooks("ip6tables")
	}

	// 3. Suntikkan Rules IPv4
	buildAndApplyRestore(false)

	// 4. Suntikkan Rules IPv6 (Jika diaktifkan)
	if config.CoreData.Config["RAF_IPV6"] == "1" {
		buildAndApplyRestore(true)
	}
}

// buildAndApplyRestore mencetak struktur firewall ke dalam format Iptables-Restore (Atomic Injection)
func buildAndApplyRestore(isIPv6 bool) {
	var buffer bytes.Buffer
	bin := "iptables-restore"
	allowSet := "RAF_ALLOW"
	denySet := "RAF_DENY"

	if isIPv6 {
		bin = "ip6tables-restore"
		allowSet = "RAF_6_ALLOW"
		denySet = "RAF_6_DENY"
	}

	// ================= BEGIN IPTABLES FORMAT =================
	buffer.WriteString("*filter\n")
	
	// Deklarasi Chain Internal RAF (Secara otomatis akan di-flush isinya oleh restore)
	buffer.WriteString(":RAF_INPUT - [0:0]\n")
	buffer.WriteString(":RAF_OUTPUT - [0:0]\n")
	buffer.WriteString(":RAF_ALLOW - [0:0]\n")
	buffer.WriteString(":RAF_DENY - [0:0]\n")
	buffer.WriteString(":RAF_ADVANCED - [0:0]\n")

	// Hook dari OS (Ditaruh di paling atas Chain INPUT/OUTPUT OS)
	buffer.WriteString("-I INPUT 1 -j RAF_INPUT\n")
	buffer.WriteString("-I OUTPUT 1 -j RAF_OUTPUT\n")

	// 1. THE CPU SAVER: STATEFUL CONNECTION
	// Drop paket cacat sedini mungkin
	buffer.WriteString("-A RAF_INPUT -m state --state INVALID -j DROP\n")
	// Terima koneksi yang sudah sah (Tidak perlu di-scan LFD/Portflood lagi = Hemat CPU 80%)
	buffer.WriteString("-A RAF_INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n")
	buffer.WriteString("-A RAF_OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n")
	// Loopback (Localhost) selalu diizinkan
	buffer.WriteString("-A RAF_INPUT -i lo -j ACCEPT\n")
	buffer.WriteString("-A RAF_OUTPUT -o lo -j ACCEPT\n")

	// 2. ROUTING PIPELINE (URUTAN EKSEKUSI)
	// (1) Cek Whitelist -> (2) Cek Blacklist -> (3) Cek Limit/Flood -> (4) Cek Port Terbuka
	buffer.WriteString("-A RAF_INPUT -j RAF_ALLOW\n")
	buffer.WriteString("-A RAF_INPUT -j RAF_DENY\n")
	buffer.WriteString("-A RAF_INPUT -j RAF_ADVANCED\n")

	// 3. ALLOW / DENY LOGIC (Menggunakan IPSET Kernel Hash)
	buffer.WriteString("-A RAF_ALLOW -m set --match-set " + allowSet + " src -j ACCEPT\n")
	buffer.WriteString("-A RAF_DENY -m set --match-set " + denySet + " src -j DROP\n")

	// 4. INTELLIGENCE HOOKS (Global Blocklists & GeoIP)
	// Saat ini GeoIP dan Blocklists biasanya berbasis IPv4
	if !isIPv6 {
		intelligence.GenerateIptablesHooks(&buffer)
	}

	// 5. PORT OPENING LOGIC & ANTI-LOCKOUT
	tcpIn := strings.Split(config.CoreData.Config["RAF_TCP_IN"], ",")
	tcpOut := strings.Split(config.CoreData.Config["RAF_TCP_OUT"], ",")
	udpIn := strings.Split(config.CoreData.Config["RAF_UDP_IN"], ",")
	udpOut := strings.Split(config.CoreData.Config["RAF_UDP_OUT"], ",")

	// INJEKSI ANTI-LOCKOUT: Paksa tambahkan Port SSH Asli & Port RoninArmor ke TCP_IN
	tcpIn = appendUnique(tcpIn, getSSHPort(), getRoninPort())

	generatePortRules(&buffer, "RAF_INPUT", "tcp", tcpIn)
	generatePortRules(&buffer, "RAF_INPUT", "udp", udpIn)
	generatePortRules(&buffer, "RAF_OUTPUT", "tcp", tcpOut)
	generatePortRules(&buffer, "RAF_OUTPUT", "udp", udpOut)

	// ICMP (Ping)
	if config.CoreData.Config["RAF_ICMP_IN"] == "1" {
		if isIPv6 {
			buffer.WriteString("-A RAF_INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT\n")
		} else {
			buffer.WriteString("-A RAF_INPUT -p icmp --icmp-type echo-request -j ACCEPT\n")
		}
	}

	
	// 6. LAYER 4 ADVANCED MITIGATIONS & SMTP EGRESS
	AppendAdvancedMitigations(&buffer, isIPv6)

	buffer.WriteString("COMMIT\n")
	// ================= END IPTABLES FORMAT =================
	



	

	// Eksekusi Command secara Atomic (Tanpa downtime / lost connection)
	// -w = Tunggu jika ada aplikasi lain yg sedang pegang lock iptables
	// -n = Noflush (Tidak akan merusak rules custom milik Docker/Plesk di chain utama)
	cmd := exec.Command(bin, "-w", "-n")
	cmd.Stdin = bytes.NewReader(buffer.Bytes())
	
	out, err := cmd.CombinedOutput()
	if err != nil {
		utils.LogError("%s Apply Failed: %s\nError Details: %s", bin, err, string(out))
	} else {
		utils.LogInfo("%s Kernel Rules Apply successfully.", bin)
	}
}

// generatePortRules mencetak rule untuk pembukaan port
func generatePortRules(buffer *bytes.Buffer, chain, proto string, ports []string) {
	for _, port := range ports {
		port = strings.TrimSpace(port)
		if port == "" { continue }
		
		flag := "--dport"
		if strings.Contains(port, ":") {
			// Jika formatnya range (misal 5000:6000), iptables membutuhkan modul '-m tcp/udp'
			buffer.WriteString("-A " + chain + " -p " + proto + " -m " + proto + " " + flag + " " + port + " -j ACCEPT\n")
		} else {
			buffer.WriteString("-A " + chain + " -p " + proto + " " + flag + " " + port + " -j ACCEPT\n")
		}
	}
}

// ==============================================================================
// 3. SYSTEM TEARDOWN (PANIC BUTTON)
// ==============================================================================

// Teardown menghapus seluruh eksistensi RAF dari Kernel Linux
func Teardown() {
	utils.LogWarn("Initiating Total Firewall Flush (Teardown Sequence)...")

	targets := []bool{false} // IPv4
	if config.CoreData.Config["RAF_IPV6"] == "1" {
		targets = append(targets, true) // IPv6
	}

	for _, isIPv6 := range targets {
		bin := "iptables"
		if isIPv6 { bin = "ip6tables" }

		// 1. Cabut Hook Utama (Pakai -w agar tidak bentrok xtables lock)
		exec.Command(bin, "-w", "-D", "INPUT", "-j", "RAF_INPUT").Run()
		exec.Command(bin, "-w", "-D", "OUTPUT", "-j", "RAF_OUTPUT").Run()

		// 2. Flush & Delete Internal Chains
		chains := []string{"RAF_INPUT", "RAF_OUTPUT", "RAF_ALLOW", "RAF_DENY", "RAF_ADVANCED"}
		for _, chain := range chains {
			exec.Command(bin, "-w", "-F", chain).Run()
		}
		for _, chain := range chains {
			exec.Command(bin, "-w", "-X", chain).Run()
		}
	}

	// 3. Hancurkan Memory Ipset (Penting agar tidak memory leak)
	exec.Command("ipset", "destroy", "RAF_ALLOW").Run()
	exec.Command("ipset", "destroy", "RAF_DENY").Run()
	exec.Command("ipset", "destroy", "RAF_6_ALLOW").Run()
	exec.Command("ipset", "destroy", "RAF_6_DENY").Run()

	utils.LogInfo("Firewall flushed and disabled. Network OS Kernel is now 100% clean.")
}
