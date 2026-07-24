// file: firewall/ipset.go
package firewall

import (
	"bytes"
	"os/exec"
	"raf/config"
	"raf/intelligence"
	"raf/utils"
)

// ==============================================================================
// 1. IPSET ATOMIC BUILDER (RAM INITIALIZATION)
// ==============================================================================

// RebuildIPSets membersihkan dan membuat ulang tabel hash di dalam kernel RAM.
// Proses ini menggunakan format batch `ipset restore` agar jutaan IP bisa dimuat dalam hitungan milidetik.
func RebuildIPSets() error {
	config.CoreData.Mutex.RLock()
	defer config.CoreData.Mutex.RUnlock()

	var buffer bytes.Buffer

	// 1. Generate Ipset Create Commands (IPv4)
	// Menggunakan maxelem 200000 agar mampu menampung ratusan ribu input manual tanpa OOM (Out Of Memory)
	buffer.WriteString("create RAF_ALLOW hash:net family inet hashsize 2048 maxelem 200000 -exist\n")
	buffer.WriteString("create RAF_DENY hash:net family inet hashsize 4096 maxelem 200000 -exist\n")
	
	// Bersihkan sisa IP lama di RAM untuk menghindari data 'Stale' / Usang
	buffer.WriteString("flush RAF_ALLOW\n")
	buffer.WriteString("flush RAF_DENY\n")

	// 2. Generate Ipset Create Commands (IPv6)
	if config.CoreData.Config["RAF_IPV6"] == "1" {
		buffer.WriteString("create RAF_6_ALLOW hash:net family inet6 hashsize 1024 maxelem 100000 -exist\n")
		buffer.WriteString("create RAF_6_DENY hash:net family inet6 hashsize 4096 maxelem 100000 -exist\n")
		buffer.WriteString("flush RAF_6_ALLOW\n")
		buffer.WriteString("flush RAF_6_DENY\n")
	}

	// 3. Pindahkan data dari RAM Go (CoreData) ke script Buffer IPSet
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

	// 4. MINTA INTELIGENCE MODULE UNTUK MENYIAPKAN TABEL MEREKA (GeoIP & Spamhaus)
	intelligence.GenerateIpsetCommands(&buffer)

	// ====================================================================
	// EKSEKUSI ATOMIC: Menjalankan semua perintah di atas dalam 1 kali eksekusi
	// Menggunakan flag `-!` (Force/Ignore Errors) agar Ipset tidak abort jika
	// menemukan IP yang bertabrakan / terduplikasi secara tidak sengaja.
	// ====================================================================
	cmd := exec.Command("ipset", "-!", "restore")
	cmd.Stdin = bytes.NewReader(buffer.Bytes())
	
	out, err := cmd.CombinedOutput()
	if err != nil {
		utils.LogError("Ipset RAM Allocation Failed: %s | Out: %s", err, string(out))
		return err
	}

	utils.LogInfo("IPSets Kernel Tables synchronized successfully (O(1) Time Complexity Achieved).")
	return nil
}

// ==============================================================================
// 2. DYNAMIC INJECTORS (ZERO-RELOAD EXECUTORS)
// ==============================================================================

// DynamicAdd menyuntikkan IP secara *live* langsung ke Kernel RAM tanpa perlu me-reload Firewall.
// listType dapat diisi dengan: "DENY" atau "ALLOW".
func DynamicAdd(ip string, listType string) {
	// Auto-Deteksi IP Type agar tidak salah masuk tabel
	isIPv6 := utils.CheckIPType(ip) == "6"
	setName := "RAF_" + listType 
	if isIPv6 { 
		setName = "RAF_6_" + listType 
	}

	// Eksekusi senyap dengan flag pengabaian error (-!)
	cmd := exec.Command("ipset", "-!", "add", setName, ip)
	if err := cmd.Run(); err == nil {
		// Logika cerdas untuk membedakan antara aksi Allow dan Deny pada teks Log
		if listType == "ALLOW" {
			utils.LogInfo("ALLOW SUCCESS: %s successfully added to whitelist [%s]", ip, setName)
		} else {
			utils.LogInfo("BLOCK SUCCESS: %s successfully added to blocklist [%s]", ip, setName)
		}
	}
}

// DynamicDel mencabut IP secara *live* dari Kernel RAM.
func DynamicDel(ip string, listType string) {
	isIPv6 := utils.CheckIPType(ip) == "6"
	setName := "RAF_" + listType 
	if isIPv6 { 
		setName = "RAF_6_" + listType 
	}

	cmd := exec.Command("ipset", "-!", "del", setName, ip)
	if err := cmd.Run(); err == nil {
		if listType == "ALLOW" {
			utils.LogInfo("REMOVAL SUCCESS: %s successfully removed from whitelist [%s]", ip, setName)
		} else {
			utils.LogInfo("REMOVAL SUCCESS: %s successfully removed from blocklist [%s]", ip, setName)
		}
	}
}

// ==============================================================================
// 3. LFD ENGINE WRAPPERS
// ==============================================================================
// Wrapper khusus untuk dipanggil oleh mesin Login Failure Daemon (LFD).

// DynamicBan adalah alias untuk menembakkan Temporary Block ke tabel DENY.
func DynamicBan(ip string) {
	DynamicAdd(ip, "DENY")
}

// DynamicUnban adalah alias untuk mencabut Temporary Block dari tabel DENY saat kadaluwarsa.
func DynamicUnban(ip string) {
	DynamicDel(ip, "DENY")
}
