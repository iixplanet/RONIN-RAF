// file: config/parser.go
package config

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"raf/utils"
)

// Definisi Konstanta File Terpusat (Diakses oleh main.go dan ipc/server.go)
const (
	AllowFile = "/usr/local/ronin/lib/raf/raf.allow"
	DenyFile  = "/usr/local/ronin/lib/raf/raf.deny"
)

// RAFData adalah struktur memori utama yang menyimpan seluruh konfigurasi & IP List
type RAFData struct {
	Config     map[string]string
	AllowList4 []string
	AllowList6 []string
	DenyList4  []string
	DenyList6  []string
	Mutex      sync.RWMutex
}

// CoreData adalah instansiasi global yang diakses oleh seluruh package
var CoreData = RAFData{
	Config: make(map[string]string),
}

// loadDefaults menyuntikkan nilai standar fail-safe jika file konfigurasi kosong/hilang
func loadDefaults() {
	defaults := map[string]string{
		"RAF_TESTING":             "0",
		"RAF_IPV6":                "1",
		"RAF_TCP_IN":              "20,21,22,25,53,80,110,143,443,465,587,993,995,2082,2083,2086,2087,2095,2096,2222,7800,8090,8443,8880,5000:6000",
		"RAF_TCP_OUT":             "20,21,22,25,53,80,110,113,443,587,993,995,2086,2087,2089,2222,2727,5000:6000",
		"RAF_UDP_IN":              "20,21,53,80,443",
		"RAF_UDP_OUT":             "20,21,53,113,123",
		"RAF_ICMP_IN":             "1",
		"RAF_PACKET_FILTER":       "1",
		
		// LFD Defaults
		"RAF_LF_DAEMON":           "1",
		"RAF_LF_INTERVAL":         "3600",
		"RAF_LF_TEMP_BAN_TIME":    "3600",
		"RAF_LF_PERM_BAN_TRIGGER": "4",
		"RAF_LF_SSHD":             "5",
		"RAF_LF_FTPD":             "10",
		"RAF_LF_EXIM":             "5",
		"RAF_LF_CPANEL":           "5",
		"RAF_LF_DIRECTADMIN":      "5",
		"RAF_LF_PLESK":            "5",
		"RAF_LF_CYBERPANEL":       "5",
		"RAF_LF_AAPANEL":          "5",
		"RAF_LF_MODSEC":           "5",
		
		// Limits
		"RAF_DENY_IP_LIMIT":       "2000",
		"RAF_TEMP_IP_LIMIT":       "1000",
		
		// SMTP Anti-Spam
		"RAF_SMTP_BLOCK":          "1",
		"RAF_SMTP_ALLOWUSER":      "root,exim,postfix,mail,mailman",
		"RAF_SMTP_PORTS":          "25,465,587",
		"RAF_SMTPAUTH_RESTRICT":   "0",
		
		// Layer 4 Anti-DDoS
		"RAF_SYNFLOOD":            "1",
		"RAF_SYNFLOOD_RATE":       "100/s",
		"RAF_SYNFLOOD_BURST":      "150",
		"RAF_PORTFLOOD":           "22;tcp;5;300",
		"RAF_CONNLIMIT":           "22;5,80;20,443;20",
		
		// Intelligence
		"RAF_CC_DENY":             "",
		"RAF_CC_ALLOW":            "",
		"RAF_CC_DENY_PORTS":       "",
		"RAF_CC_ALLOW_PORTS":      "",
		"RAF_BLOCKLIST_ENABLE":    "1",
		"RAF_BLOCKLIST_INTERVAL":  "86400",
		"RAF_BL_SPAMDROP":         "https://www.spamhaus.org/drop/drop.txt",
		"RAF_BL_DSHIELD":          "https://www.dshield.org/block.txt",
		"RAF_BL_CUSTOM":           "",
	}

	for k, v := range defaults {
		CoreData.Config[k] = v
	}
}

// LoadAll mem-parsing file konfigurasi utama, raf.allow, dan raf.deny secara Thread-Safe
func LoadAll(configPath, allowPath, denyPath string) {
	CoreData.Mutex.Lock()
	defer CoreData.Mutex.Unlock()

	// 1. Inisialisasi peta konfigurasi dengan Defaults
	CoreData.Config = make(map[string]string)
	loadDefaults()

	// 2. Timpa Defaults dengan nilai riil dari config.ronin
	file, err := os.Open(configPath)
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 && strings.HasPrefix(strings.TrimSpace(parts[0]), "RAF_") {
				key := strings.TrimSpace(parts[0])
				// Bersihkan kutip ganda/tunggal yang mungkin diketik user
				val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				CoreData.Config[key] = val
			}
		}
		file.Close()
	} else {
		utils.LogWarn("Config file %s not found. Using Fail-Safe Built-in Defaults.", configPath)
	}

	// 3. Bersihkan RAM List lama (Jika proses ini adalah Hot-Reload)
	CoreData.AllowList4, CoreData.AllowList6 = []string{}, []string{}
	CoreData.DenyList4, CoreData.DenyList6 = []string{}, []string{}

	// 4. Injeksi Otomatis Anti-Lockout (IP Interface Lokal & Loopback) ke dalam AllowList
	localIPs := utils.GetLocalIPs()
	for _, ip := range localIPs {
		ipType := utils.CheckIPType(ip)
		if ipType == "4" {
			CoreData.AllowList4 = append(CoreData.AllowList4, ip)
		} else if ipType == "6" {
			CoreData.AllowList6 = append(CoreData.AllowList6, ip)
		}
	}

	// 5. Eksekusi Parsing File Allow & Deny Manual
	parseListFile(allowPath, &CoreData.AllowList4, &CoreData.AllowList6)
	parseListFile(denyPath, &CoreData.DenyList4, &CoreData.DenyList6)
}

// parseListFile membaca list IP dan mengkategorikannya ke IPv4 atau IPv6 secara aman
func parseListFile(path string, list4, list6 *[]string) {
	file, err := os.Open(path)
	if err != nil {
		utils.LogWarn("File list not found or inaccessible: %s", path)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Abaikan baris kosong atau komentar utuh
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Filter komentar di ujung baris (misal: "1.2.3.4 # Admin IP")
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// Validasi format IP / CIDR
		ipType := utils.CheckIPType(line)
		if ipType == "4" {
			*list4 = append(*list4, line)
		} else if ipType == "6" {
			*list6 = append(*list6, line)
		}
	}
}
