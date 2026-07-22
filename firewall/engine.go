// file: firewall/engine.go
package firewall

import (
	"bytes"
	"os/exec"
	"strings"
	"raf/config"
	"raf/intelligence"
	"raf/utils"
)

// ApplyIptables membangun dan meng-inject rules ke kernel Linux
func ApplyIptables() {
	// Rebuild IPSet terlebih dahulu
	if err := RebuildIPSets(); err != nil {
		utils.LogWarn("Warning: IPSet build encountered issues. Firewall might operate in degraded mode.")
	}

	config.CoreData.Mutex.RLock()
	defer config.CoreData.Mutex.RUnlock()

	// Teardown hook lama (jika ada) agar tidak duplikat
	exec.Command("iptables", "-D", "INPUT", "-j", "RAF_INPUT").Run()
	exec.Command("iptables", "-D", "OUTPUT", "-j", "RAF_OUTPUT").Run()
	if config.CoreData.Config["RAF_IPV6"] == "1" {
		exec.Command("ip6tables", "-D", "INPUT", "-j", "RAF_INPUT").Run()
		exec.Command("ip6tables", "-D", "OUTPUT", "-j", "RAF_OUTPUT").Run()
	}

	utils.LogInfo("Building Stateful Packet Inspection (SPI) Rules...")

	// 1. Eksekusi untuk IPv4
	buildAndApplyRestore(false)

	// 2. Eksekusi untuk IPv6 (Jika diaktifkan)
	if config.CoreData.Config["RAF_IPV6"] == "1" {
		buildAndApplyRestore(true)
	}
}


// file: firewall/engine.go (Bagian yang diubah)

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

	buffer.WriteString("*filter\n")
	buffer.WriteString(":RAF_INPUT - [0:0]\n")
	buffer.WriteString(":RAF_OUTPUT - [0:0]\n")
	buffer.WriteString(":RAF_ALLOW - [0:0]\n")
	buffer.WriteString(":RAF_DENY - [0:0]\n")
	buffer.WriteString(":RAF_ADVANCED - [0:0]\n")

	buffer.WriteString("-I INPUT 1 -j RAF_INPUT\n")
	buffer.WriteString("-I OUTPUT 1 -j RAF_OUTPUT\n")

	// 1. CPU SAVER: STATEFUL CONNECTION
	buffer.WriteString("-A RAF_INPUT -m state --state INVALID -j DROP\n")
	buffer.WriteString("-A RAF_INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n")
	buffer.WriteString("-A RAF_OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n")
	buffer.WriteString("-A RAF_INPUT -i lo -j ACCEPT\n")
	buffer.WriteString("-A RAF_OUTPUT -o lo -j ACCEPT\n")

	// 2. ROUTING PIPELINE
	buffer.WriteString("-A RAF_INPUT -j RAF_ALLOW\n")
	buffer.WriteString("-A RAF_INPUT -j RAF_DENY\n")
	buffer.WriteString("-A RAF_INPUT -j RAF_ADVANCED\n")

	// 3. ALLOW / DENY LOGIC
	buffer.WriteString("-A RAF_ALLOW -m set --match-set " + allowSet + " src -j ACCEPT\n")
	buffer.WriteString("-A RAF_DENY -m set --match-set " + denySet + " src -j DROP\n")

	// 4. MINTA INTELLIGENCE MODULE UNTUK MENGKAITKAN IPSET KE IPTABLES (NEW!)
	if !isIPv6 {
		intelligence.GenerateIptablesHooks(&buffer)
	}

	// 5. PORT OPENING LOGIC
	tcpIn := strings.Split(config.CoreData.Config["RAF_TCP_IN"], ",")
	tcpOut := strings.Split(config.CoreData.Config["RAF_TCP_OUT"], ",")
	udpIn := strings.Split(config.CoreData.Config["RAF_UDP_IN"], ",")
	udpOut := strings.Split(config.CoreData.Config["RAF_UDP_OUT"], ",")

	generatePortRules(&buffer, "RAF_INPUT", "tcp", tcpIn)
	generatePortRules(&buffer, "RAF_INPUT", "udp", udpIn)
	generatePortRules(&buffer, "RAF_OUTPUT", "tcp", tcpOut)
	generatePortRules(&buffer, "RAF_OUTPUT", "udp", udpOut)

	if config.CoreData.Config["RAF_ICMP_IN"] == "1" {
		if isIPv6 {
			buffer.WriteString("-A RAF_INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT\n")
		} else {
			buffer.WriteString("-A RAF_INPUT -p icmp --icmp-type echo-request -j ACCEPT\n")
		}
	}

	// LAYER 4 ADVANCED MITIGATIONS
	AppendAdvancedMitigations(&buffer, isIPv6)

	buffer.WriteString("COMMIT\n")

	cmd := exec.Command(bin, "-n")
	cmd.Stdin = bytes.NewReader(buffer.Bytes())
	
	out, err := cmd.CombinedOutput()
	if err != nil {
		utils.LogError("%s Apply Failed: %s\nError Details: %s", bin, err, string(out))
	} else {
		utils.LogInfo("%s Kernel Rules Apply successfully.", bin)
	}
}
	

	

func generatePortRules(buffer *bytes.Buffer, chain, proto string, ports []string) {
	for _, port := range ports {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		// Support port range (ex: 6000:7000)
		flag := "--dport"
		if strings.Contains(port, ":") {
			// iptables range butuh modul tambahan "-m tcp" atau "udp"
			buffer.WriteString("-A " + chain + " -p " + proto + " -m " + proto + " " + flag + " " + port + " -j ACCEPT\n")
		} else {
			buffer.WriteString("-A " + chain + " -p " + proto + " " + flag + " " + port + " -j ACCEPT\n")
		}
	}
}
