// file: firewall/ipset.go (Perbarui argumen exec.Command)
package firewall

import (
	"bytes"
	"os/exec"
	"raf/config"
	"raf/intelligence"
	"raf/utils"
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

	// 3. Populate Allow/Deny Lists
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

	// 4. MINTA INTELIGENCE MODULE UNTUK MENYIAPKAN TABEL IPSET MEREKA
	intelligence.GenerateIpsetCommands(&buffer)

	// Execute Ipset Restore in one atomic block
	// PERUBAHAN: Tambahkan "-!" untuk mengabaikan error force exist
	cmd := exec.Command("ipset", "-!", "restore")
	cmd.Stdin = bytes.NewReader(buffer.Bytes())
	
	out, err := cmd.CombinedOutput()
	if err != nil {
		utils.LogError("Ipset Restore Failed: %s | Out: %s", err, string(out))
		return err
	}

	utils.LogInfo("IPSets synchronized successfully (Memory Optimized).")
	return nil
}

// DynamicBan menambahkan IP ke ipset secara instan (Untuk LFD)
func DynamicBan(ip string) {
	isIPv6 := utils.CheckIPType(ip) == "6"
	setName := "RAF_DENY"
	if isIPv6 {
		setName = "RAF_6_DENY"
	}

	// PERUBAHAN: Tambahkan "-!"
	cmd := exec.Command("ipset", "-!", "add", setName, ip)
	if err := cmd.Run(); err == nil {
		utils.LogInfo("RAF LFD INSTANT BLOCK: %s apply to Kernel IPSet.", ip)
	}
}

// DynamicUnban menghapus IP dari ipset (Untuk Temp Ban Expiration)
func DynamicUnban(ip string) {
	isIPv6 := utils.CheckIPType(ip) == "6"
	setName := "RAF_DENY"
	if isIPv6 {
		setName = "RAF_6_DENY"
	}

	// PERUBAHAN: Tambahkan "-!"
	cmd := exec.Command("ipset", "-!", "del", setName, ip)
	if err := cmd.Run(); err == nil {
		utils.LogInfo("RAF LFD AUTO-UNBAN: %s removed from Kernel IPSet.", ip)
	}
}
