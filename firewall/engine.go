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

// getSSHPort membaca port asli dari sistem
func getSSHPort() string {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Port ") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Port "))
			}
		}
	}
	return "22"
}

// getRoninPort membaca port web dashboard
func getRoninPort() string {
	data, err := os.ReadFile("/usr/local/ronin/config.ronin")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "listen_port") {
				parts := strings.Split(line, "=")
				if len(parts) == 2 { return strings.Trim(strings.TrimSpace(parts[1]), `"'`) }
			}
		}
	}
	return "5029" // fallback default
}

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

func ApplyIptables() {
	if err := RebuildIPSets(); err != nil {
		utils.LogWarn("IPSet build encountered issues. Firewall might operate in degraded mode.")
	}

	config.CoreData.Mutex.RLock()
	defer config.CoreData.Mutex.RUnlock()

	exec.Command("iptables", "-D", "INPUT", "-j", "RAF_INPUT").Run()
	exec.Command("iptables", "-D", "OUTPUT", "-j", "RAF_OUTPUT").Run()
	if config.CoreData.Config["RAF_IPV6"] == "1" {
		exec.Command("ip6tables", "-D", "INPUT", "-j", "RAF_INPUT").Run()
		exec.Command("ip6tables", "-D", "OUTPUT", "-j", "RAF_OUTPUT").Run()
	}

	utils.LogInfo("Building Stateful Packet Inspection (SPI) Rules...")
	buildAndApplyRestore(false)
	if config.CoreData.Config["RAF_IPV6"] == "1" {
		buildAndApplyRestore(true)
	}
}

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

	buffer.WriteString("-A RAF_INPUT -m state --state INVALID -j DROP\n")
	buffer.WriteString("-A RAF_INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n")
	buffer.WriteString("-A RAF_OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n")
	buffer.WriteString("-A RAF_INPUT -i lo -j ACCEPT\n")
	buffer.WriteString("-A RAF_OUTPUT -o lo -j ACCEPT\n")

	buffer.WriteString("-A RAF_INPUT -j RAF_ALLOW\n")
	buffer.WriteString("-A RAF_INPUT -j RAF_DENY\n")
	buffer.WriteString("-A RAF_INPUT -j RAF_ADVANCED\n")

	buffer.WriteString("-A RAF_ALLOW -m set --match-set " + allowSet + " src -j ACCEPT\n")
	buffer.WriteString("-A RAF_DENY -m set --match-set " + denySet + " src -j DROP\n")

	if !isIPv6 { intelligence.GenerateIptablesHooks(&buffer) }

	// PORT INJECTION DENGAN ANTI-LOCKOUT
	tcpIn := strings.Split(config.CoreData.Config["RAF_TCP_IN"], ",")
	tcpOut := strings.Split(config.CoreData.Config["RAF_TCP_OUT"], ",")
	udpIn := strings.Split(config.CoreData.Config["RAF_UDP_IN"], ",")
	udpOut := strings.Split(config.CoreData.Config["RAF_UDP_OUT"], ",")

	tcpIn = appendUnique(tcpIn, getSSHPort(), getRoninPort()) // INJECT OTOMATIS

	generatePortRules(&buffer, "RAF_INPUT", "tcp", tcpIn)
	generatePortRules(&buffer, "RAF_INPUT", "udp", udpIn)
	generatePortRules(&buffer, "RAF_OUTPUT", "tcp", tcpOut)
	generatePortRules(&buffer, "RAF_OUTPUT", "udp", udpOut)

	if config.CoreData.Config["RAF_ICMP_IN"] == "1" {
		if isIPv6 { buffer.WriteString("-A RAF_INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT\n")
		} else { buffer.WriteString("-A RAF_INPUT -p icmp --icmp-type echo-request -j ACCEPT\n") }
	}

	AppendAdvancedMitigations(&buffer, isIPv6)
	buffer.WriteString("COMMIT\n")

	cmd := exec.Command(bin, "-n")
	cmd.Stdin = bytes.NewReader(buffer.Bytes())
	if err := cmd.Run(); err == nil {
		utils.LogInfo("%s Kernel Rules Apply successfully.", bin)
	}
}

func generatePortRules(buffer *bytes.Buffer, chain, proto string, ports []string) {
	for _, port := range ports {
		port = strings.TrimSpace(port)
		if port == "" { continue }
		flag := "--dport"
		if strings.Contains(port, ":") {
			buffer.WriteString("-A " + chain + " -p " + proto + " -m " + proto + " " + flag + " " + port + " -j ACCEPT\n")
		} else {
			buffer.WriteString("-A " + chain + " -p " + proto + " " + flag + " " + port + " -j ACCEPT\n")
		}
	}
}

func Teardown() {
	utils.LogWarn("Initiating Total Firewall Flush (Teardown Sequence)...")
	targets := []bool{false} 
	if config.CoreData.Config["RAF_IPV6"] == "1" { targets = append(targets, true) }

	for _, isIPv6 := range targets {
		bin := "iptables"
		if isIPv6 { bin = "ip6tables" }
		exec.Command(bin, "-D", "INPUT", "-j", "RAF_INPUT").Run()
		exec.Command(bin, "-D", "OUTPUT", "-j", "RAF_OUTPUT").Run()
		chains := []string{"RAF_INPUT", "RAF_OUTPUT", "RAF_ALLOW", "RAF_DENY", "RAF_ADVANCED"}
		for _, chain := range chains { exec.Command(bin, "-F", chain).Run() }
		for _, chain := range chains { exec.Command(bin, "-X", chain).Run() }
	}
	exec.Command("ipset", "destroy", "RAF_ALLOW").Run()
	exec.Command("ipset", "destroy", "RAF_DENY").Run()
	exec.Command("ipset", "destroy", "RAF_6_ALLOW").Run()
	exec.Command("ipset", "destroy", "RAF_6_DENY").Run()
	utils.LogInfo("RAF Firewall flushed and disabled.")
}
