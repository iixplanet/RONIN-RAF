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
	"strconv"
	"strings"
	"time"
	"raf/config"
	"raf/utils"
)

const ZoneDir = "/usr/local/ronin/lib/raf/zone"

type Blocklist struct {
	Name     string
	Interval time.Duration
	URL      string
}

var (
	ActiveBlocklists   []Blocklist
	BlocklistEnabled   bool
	ActiveCCDeny       []string
	ActiveCCAllow      []string
	ActiveCCDenyPorts  map[string]string
	ActiveCCAllowPorts map[string]string
	
	// Ultra-Precise IPv4 & CIDR Regex (Mencegah false positive)
	ipv4Regex = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[1-2]?[0-9]|3[0-2]))?\b`)
)

// InitAndParse membaca konfigurasi RAF dan menyiapkan data Intelijen sebelum Firewall di-apply
func InitAndParse() {
	config.CoreData.Mutex.RLock()
	ccDeny := config.CoreData.Config["RAF_CC_DENY"]
	ccAllow := config.CoreData.Config["RAF_CC_ALLOW"]
	ccDenyPorts := config.CoreData.Config["RAF_CC_DENY_PORTS"]
	ccAllowPorts := config.CoreData.Config["RAF_CC_ALLOW_PORTS"]
	
	blEnabledStr := config.CoreData.Config["RAF_BLOCKLIST_ENABLE"]
	blGlobalIntervalStr := config.CoreData.Config["RAF_BLOCKLIST_INTERVAL"]
	urlSpamdrop := config.CoreData.Config["RAF_BL_SPAMDROP"]
	urlDshield := config.CoreData.Config["RAF_BL_DSHIELD"]
	urlCustom := config.CoreData.Config["RAF_BL_CUSTOM"]
	config.CoreData.Mutex.RUnlock()

	// 1. Status Global Blocklist
	BlocklistEnabled = (blEnabledStr == "1" || strings.ToLower(blEnabledStr) == "true")
	globalInterval := 86400 // Default 24 Jam
	if val, err := strconv.Atoi(blGlobalIntervalStr); err == nil && val > 0 {
		globalInterval = val
	}

	// 2. Load Blocklists Data dari Dashboard Settings
	ActiveBlocklists = []Blocklist{}
	if BlocklistEnabled {
		if urlSpamdrop != "" {
			ActiveBlocklists = append(ActiveBlocklists, Blocklist{Name: "SPAMDROP", Interval: time.Duration(globalInterval) * time.Second, URL: urlSpamdrop})
		}
		if urlDshield != "" {
			ActiveBlocklists = append(ActiveBlocklists, Blocklist{Name: "DSHIELD", Interval: time.Duration(globalInterval) * time.Second, URL: urlDshield})
		}
		if urlCustom != "" {
			ActiveBlocklists = append(ActiveBlocklists, Blocklist{Name: "CUSTOM_INTEL", Interval: time.Duration(globalInterval) * time.Second, URL: urlCustom})
		}
	}

	// 3. Parse Country Codes (GeoIP)
	ActiveCCDeny = parseCC(ccDeny)
	ActiveCCAllow = parseCC(ccAllow)
	ActiveCCDenyPorts = parseCCPorts(ccDenyPorts)
	ActiveCCAllowPorts = parseCCPorts(ccAllowPorts)

	// Gabungkan semua kode negara unik agar IPSet-nya disiapkan di Kernel
	mergeUniqueCC(&ActiveCCDeny, ActiveCCDenyPorts)
	mergeUniqueCC(&ActiveCCAllow, ActiveCCAllowPorts)
}

func parseCC(raw string) []string {
	var list []string
	for _, cc := range strings.Split(raw, ",") {
		cc = strings.TrimSpace(strings.ToUpper(cc))
		if cc != "" { list = append(list, cc) }
	}
	return list
}

func parseCCPorts(raw string) map[string]string {
	res := make(map[string]string)
	raw = strings.TrimSpace(raw)
	if raw == "" { return res }

	rules := strings.FieldsFunc(raw, func(c rune) bool { return c == '|' || c == ' ' })
	for _, rule := range rules {
		parts := strings.Split(rule, ":")
		if len(parts) == 2 {
			ports := strings.TrimSpace(parts[1])
			for _, cc := range strings.Split(parts[0], ",") {
				cc = strings.TrimSpace(strings.ToUpper(cc))
				if cc != "" { res[cc] = ports }
			}
		}
	}
	return res
}

func mergeUniqueCC(mainList *[]string, portList map[string]string) {
	existing := make(map[string]bool)
	for _, cc := range *mainList { existing[cc] = true }
	for cc := range portList {
		if !existing[cc] {
			*mainList = append(*mainList, cc)
			existing[cc] = true
		}
	}
}

// GenerateIpsetCommands membuat fondasi tabel memori kernel secara instan (Atomic)
func GenerateIpsetCommands(buffer *bytes.Buffer) {
	// CC Deny & CC Allow membutuhkan ruang memori menengah (maxelem 200000)
	for _, cc := range ActiveCCDeny {
		buffer.WriteString(fmt.Sprintf("create cc_%s hash:net family inet hashsize 2048 maxelem 200000 -exist\nflush cc_%s\n", cc, cc))
	}
	for _, cc := range ActiveCCAllow {
		buffer.WriteString(fmt.Sprintf("create cc_%s hash:net family inet hashsize 2048 maxelem 200000 -exist\nflush cc_%s\n", cc, cc))
	}
	
	// Global Blocklists
	if BlocklistEnabled {
		for _, bl := range ActiveBlocklists {
			buffer.WriteString(fmt.Sprintf("create bl_%s hash:net family inet hashsize 8192 maxelem 500000 -exist\n", bl.Name))
		}
	}
}

// GenerateIptablesHooks mengaitkan memori IPSet ke dalam skema Iptables
func GenerateIptablesHooks(buffer *bytes.Buffer) {
	if BlocklistEnabled {
		for _, bl := range ActiveBlocklists {
			buffer.WriteString(fmt.Sprintf("-A RAF_INPUT -m set --match-set bl_%s src -j DROP\n", bl.Name))
		}
	}

	for _, cc := range ActiveCCDeny {
		if ports, exists := ActiveCCDenyPorts[cc]; exists {
			buffer.WriteString(fmt.Sprintf("-A RAF_DENY -m set --match-set cc_%s src -p tcp -m multiport --dports %s -j DROP\n", cc, ports))
			buffer.WriteString(fmt.Sprintf("-A RAF_DENY -m set --match-set cc_%s src -p udp -m multiport --dports %s -j DROP\n", cc, ports))
		} else {
			buffer.WriteString(fmt.Sprintf("-A RAF_DENY -m set --match-set cc_%s src -j DROP\n", cc))
		}
	}

	for _, cc := range ActiveCCAllow {
		if ports, exists := ActiveCCAllowPorts[cc]; exists {
			buffer.WriteString(fmt.Sprintf("-A RAF_ALLOW -m set --match-set cc_%s src -p tcp -m multiport --dports %s -j ACCEPT\n", cc, ports))
			buffer.WriteString(fmt.Sprintf("-A RAF_ALLOW -m set --match-set cc_%s src -p udp -m multiport --dports %s -j ACCEPT\n", cc, ports))
		} else {
			buffer.WriteString(fmt.Sprintf("-A RAF_ALLOW -m set --match-set cc_%s src -j ACCEPT\n", cc))
		}
	}
}

// StartBackgroundWorkers memulai semua proses download intelligence tanpa membuat Daemon Hang
func StartBackgroundWorkers() {
	if len(ActiveCCDeny) > 0 { go loadZonesToIpset(ActiveCCDeny) }
	if len(ActiveCCAllow) > 0 { go loadZonesToIpset(ActiveCCAllow) }

	if BlocklistEnabled {
		for _, bl := range ActiveBlocklists {
			go func(b Blocklist) {
				downloadAndInjectBlocklist(b)
				for {
					time.Sleep(b.Interval)
					downloadAndInjectBlocklist(b)
				}
			}(bl)
		}
	} else {
		utils.LogInfo("Global Intel: Threat Feed auto-update is currently Disabled in config.")
	}
}

// downloadZoneFile mengunduh blok IP Negara secara otomatis dari ipdeny.com
func downloadZoneFile(cc string) error {
	os.MkdirAll(ZoneDir, 0755)
	url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", strings.ToLower(cc))
	utils.LogInfo("GeoIP Intel: Downloading IP database for country [%s]...", cc)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil { return err }
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; RoninArmor/1.0)")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return fmt.Errorf("failed to fetch zone. HTTP Status: %v", resp.StatusCode)
	}
	defer resp.Body.Close()

	path := filepath.Join(ZoneDir, strings.ToLower(cc)+".zone")
	out, err := os.Create(path)
	if err != nil { return err }
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// loadZonesToIpset membaca file data negara, otomatis mendownload jika belum ada
func loadZonesToIpset(ccList []string) {
	var buffer bytes.Buffer
	count := 0

	for _, cc := range ccList {
		path := filepath.Join(ZoneDir, strings.ToLower(cc)+".zone")
		
		// AUTO-DOWNLOAD: Jika file .zone belum ada, download langsung!
		if _, err := os.Stat(path); os.IsNotExist(err) {
			errDL := downloadZoneFile(cc)
			if errDL != nil {
				utils.LogError("GeoIP Intel: Failed to download zone [%s]: %v", cc, errDL)
				continue // Lewati negara ini jika gagal didownload
			}
		}

		file, err := os.Open(path)
		if err != nil {
			utils.LogWarn("GeoIP Zone file is unreadable: %s", path)
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
		cmd := exec.Command("ipset", "-!", "restore")
		cmd.Stdin = bytes.NewReader(buffer.Bytes())
		if err := cmd.Run(); err == nil {
			utils.LogInfo("GeoIP Intel: Successfully injected %d Country IP Blocks into memory.", count)
		} else {
			utils.LogError("GeoIP Intel: Failed to inject IP blocks to Kernel.")
		}
	}
}

// downloadAndInjectBlocklist mengunduh dan menyuntikkan IP jahat (Safe Flush Mechanism)
func downloadAndInjectBlocklist(bl Blocklist) {
	utils.LogInfo("Global Intel: Downloading Threat Feed [%s]...", bl.Name)

	req, err := http.NewRequest("GET", bl.URL, nil)
	if err != nil { return }
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; RoninArmor/1.0; +https://roninarmor.com)")

	client := &http.Client{ Timeout: 45 * time.Second }
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		utils.LogWarn("Global Intel: Failed to fetch [%s] -> Retaining old IP data.", bl.Name)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil { return }

	ips := ipv4Regex.FindAllString(string(bodyBytes), -1)

	if len(ips) > 0 {
		var buffer bytes.Buffer
		buffer.WriteString(fmt.Sprintf("flush bl_%s\n", bl.Name)) 

		for _, ip := range ips {
			buffer.WriteString(fmt.Sprintf("add bl_%s %s -exist\n", bl.Name, ip))
		}

		cmd := exec.Command("ipset", "-!", "restore")
		cmd.Stdin = bytes.NewReader(buffer.Bytes())
		if err := cmd.Run(); err == nil {
			utils.LogInfo("Global Intel: Feed [%s] updated! Loaded %d Malicious IPs.", bl.Name, len(ips))
		} else {
			utils.LogError("Global Intel: Failed to inject [%s] to IPSet.", bl.Name)
		}
	} else {
		utils.LogWarn("Global Intel: Feed [%s] returned 0 valid IPs.", bl.Name)
	}
}
