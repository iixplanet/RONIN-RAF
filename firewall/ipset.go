// file: firewall/ipset.go
package firewall

import (
	"bytes"
	"os/exec"
	"raf/utils"
	"raf/config"
)

// RebuildIPSets membersihkan dan membuat ulang tabel ipset di dalam kernel
func RebuildIPSets() error {
	config.CoreData.Mutex.RLock()
	defer config.CoreData.Mutex.RUnlock()

	var buffer bytes.Buffer

	// 1. Generate Ipset Create Commands (IPv4)
	buffer.WriteString("create RAF_ALLOW hash:net family inet hashsize 1024 maxelem 65536 -exist\n")
	buffer.WriteString("create RAF_DENY hash:net family inet hashsize 4096 maxelem 100000 -exist\n")
	buffer.WriteString("flush RAF_ALLOW\n")
	buffer.WriteString("flush RAF_DENY\n")

	// 2. Generate Ipset Create Commands (IPv6)
	if config.CoreData.Config["RAF_IPV6"] == "1" {
		buffer.WriteString("create RAF_6_ALLOW hash:net family inet6 hashsize 1024 maxelem 65536 -exist\n")
		buffer.WriteString("create RAF_6_DENY hash:net family inet6 hashsize 4096 maxelem 100000 -exist\n")
		buffer.WriteString("flush RAF_6_ALLOW\n")
		buffer.WriteString("flush RAF_6_DENY\n")
	}

	// 3. Populate Allow Lists (IPv4 & IPv6)
	for _, ip := range config.CoreData.AllowList4 {
		buffer.WriteString("add RAF_ALLOW " + ip + " -exist\n")
	}
	for _, ip := range config.CoreData.DenyList4 {
		buffer.WriteString("add RAF_DENY " + ip + " -exist\n")
	}

	if config.CoreData.Config["RAF_IPV6"] == "1" {
		for _, ip := range config.CoreData.AllowList6 {
			buffer.WriteString("add RAF_6_ALLOW " + ip + " -exist\n")
		}
		for _, ip := range config.CoreData.DenyList6 {
			buffer.WriteString("add RAF_6_DENY " + ip + " -exist\n")
		}
	}

	// Execute Ipset Restore in one atomic block
	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = bytes.NewReader(buffer.Bytes())
	
	out, err := cmd.CombinedOutput()
	if err != nil {
		utils.LogError("Ipset Restore Failed: %s | Out: %s", err, string(out))
		return err
	}

	utils.LogInfo("IPSets synchronized successfully (Memory Optimized).")
	return nil
}