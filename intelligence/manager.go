// file: intelligence/manager.go
package intelligence

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"raf/config"
	"raf/utils"
)

const (
	BlocklistFile = "/usr/local/ronin/lib/raf/raf.blocklists"
	ZoneDir       = "/usr/local/ronin/lib/raf/zone"
)

type Blocklist struct {
	Name     string
	Interval time.Duration
	URL      string
}

var (
	ActiveBlocklists []Blocklist
	ActiveCCDeny     []string
	ActiveCCAllow    []string
	ipv4Regex        = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/[0-9]{1,2})?\b`)
)

// InitAndParse membaca konfigurasi dan menyiapkan data Intelijen sebelum Firewall di-apply
func InitAndParse() {
	// Buat file blocklist default jika belum ada
	if _, err := os.Stat(BlocklistFile); os.IsNotExist(err) {
		defaultBL := "# Format: NAME|INTERVAL(seconds)|MAX|URL\n" +
			"SPAMDROP|86400|0|https://www.spamhaus.org/drop/drop.txt\n" +
			"DSHIELD|86400|0|https://www.dshield.org/block.txt\n"
		os.WriteFile(BlocklistFile, []byte(defaultBL), 0644)
	}

	// 1. Parse Blocklists
	ActiveBlocklists = []Blocklist{}
	file, err := os.Open(BlocklistFile)
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) >= 4 {
				interval := 86400 // Default 1 hari
				fmt.Sscanf(parts[1], "%d", &interval)
				ActiveBlocklists = append(ActiveBlocklists, Blocklist{
					Name:     strings.ToUpper(strings.TrimSpace(parts[0])),
					Interval: time.Duration(interval) * time.Second,
					URL:      strings.TrimSpace(parts[3]),
				})
			}
		}
		file.Close()
	}

	// 2. Parse Country Codes (GeoIP)
	config.CoreData.Mutex.RLock()
	ccDeny := config.CoreData.Config["RAF_CC_DENY"]
	ccAllow := config.CoreData.Config["RAF_CC_ALLOW"]
	config.CoreData.Mutex.RUnlock()

	ActiveCCDeny = parseCC(ccDeny)
	ActiveCCAllow = parseCC(ccAllow)
}

func parseCC(raw string) []string {
	var list []string
	for _, cc := range strings.Split(raw, ",") {
		cc = strings.TrimSpace(strings.ToUpper(cc))
		if cc != "" {
			list = append(list, cc)
		}
	}
	return list
}

// GenerateIpsetCommands dipanggil oleh firewall/ipset.go untuk membuat tabel hash kosong terlebih dahulu
func GenerateIpsetCommands(buffer *bytes.Buffer) {
	// Prepare IPsets for Country Codes
	for _, cc := range ActiveCCDeny {
		buffer.WriteString(fmt.Sprintf("create cc_%s hash:net family inet hashsize 2048 maxelem 200000 -exist\nflush cc_%s\n", cc, cc))
	}
	for _, cc := range ActiveCCAllow {
		buffer.WriteString(fmt.Sprintf("create cc_%s hash:net family inet hashsize 2048 maxelem 200000 -exist\nflush cc_%s\n", cc, cc))
	}
	// Prepare IPsets for Blocklists
	for _, bl := range ActiveBlocklists {
		buffer.WriteString(fmt.Sprintf("create bl_%s hash:net family inet hashsize 4096 maxelem 200000 -exist\nflush bl_%s\n", bl.Name, bl.Name))
	}
}

// GenerateIptablesHooks dipanggil oleh firewall/engine.go untuk menghubungkan IPSet ke rule kernel
func GenerateIptablesHooks(buffer *bytes.Buffer) {
	for _, bl := range ActiveBlocklists {
		buffer.WriteString(fmt.Sprintf("-A RAF_INPUT -m set --match-set bl_%s src -j DROP\n", bl.Name))
	}
	for _, cc := range ActiveCCDeny {
		buffer.WriteString(fmt.Sprintf("-A RAF_DENY -m set --match-set cc_%s src -j DROP\n", cc))
	}
	for _, cc := range ActiveCCAllow {
		buffer.WriteString(fmt.Sprintf("-A RAF_ALLOW -m set --match-set cc_%s src -j ACCEPT\n", cc))
	}
}

// StartBackgroundWorkers memulai download Blocklist & meload GeoIP Zone secara asynchronous (Tidak bikin server hang)
func StartBackgroundWorkers() {
	// Load GeoIP (Country Zones) langsung
	go loadZonesToIpset(ActiveCCDeny)
	go loadZonesToIpset(ActiveCCAllow)

	// Mulai penjadwalan download Global Blocklists
	for _, bl := range ActiveBlocklists {
		go func(b Blocklist) {
			for {
				downloadAndInjectBlocklist(b)
				time.Sleep(b.Interval)
			}
		}(bl)
	}
}

// loadZonesToIpset membaca file contoh: /usr/local/ronin/lib/raf/zone/cn.zone
func loadZonesToIpset(ccList []string) {
	var buffer bytes.Buffer
	count := 0

	for _, cc := range ccList {
		path := filepath.Join(ZoneDir, strings.ToLower(cc)+".zone")
		file, err := os.Open(path)
		if err != nil {
			utils.LogWarn("GeoIP Zone file not found: %s", path)
			continue
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ipv4Regex.MatchString(ip) {
				buffer.WriteString(fmt.Sprintf("add cc_%s %s -exist\n", cc, ip))
				count++
			}
		}
		file.Close()
	}

	if count > 0 {
		cmd := exec.Command("ipset", "restore")
		cmd.Stdin = bytes.NewReader(buffer.Bytes())
		if err := cmd.Run(); err == nil {
			utils.LogInfo("GeoIP Intel: Successfully injected %d Country IP Blocks.", count)
		}
	}
}

// downloadAndInjectBlocklist mengambil URL eksternal, regex semua IP, dan masukkan ke kernel
func downloadAndInjectBlocklist(bl Blocklist) {
	utils.LogInfo("Global Intel: Downloading Threat Feed [%s]...", bl.Name)

	resp, err := http.Get(bl.URL)
	if err != nil {
		utils.LogWarn("Global Intel: Failed to fetch [%s] -> %v", bl.Name, err)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	ips := ipv4Regex.FindAllString(string(bodyBytes), -1)

	if len(ips) > 0 {
		var buffer bytes.Buffer
		buffer.WriteString(fmt.Sprintf("flush bl_%s\n", bl.Name)) // Bersihkan versi lama

		for _, ip := range ips {
			buffer.WriteString(fmt.Sprintf("add bl_%s %s -exist\n", bl.Name, ip))
		}

		cmd := exec.Command("ipset", "restore")
		cmd.Stdin = bytes.NewReader(buffer.Bytes())
		if err := cmd.Run(); err == nil {
			utils.LogInfo("Global Intel: Feed [%s] updated! Loaded %d Malicious IPs into Kernel.", bl.Name, len(ips))
		} else {
			utils.LogError("Global Intel: Failed to inject [%s] to IPSet.", bl.Name)
		}
	}
}