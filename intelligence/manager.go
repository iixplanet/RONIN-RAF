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
	ActiveBlocklists   []Blocklist
	BlocklistEnabled   bool
	ActiveCCDeny       []string
	ActiveCCAllow      []string
	ActiveCCDenyPorts  map[string]string
	ActiveCCAllowPorts map[string]string
	ipv4Regex          = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/[0-9]{1,2})?\b`)
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
	config.CoreData.Mutex.RUnlock()

	// 1. Parse Status Global Blocklist
	BlocklistEnabled = (blEnabledStr == "1")
	globalInterval := 86400
	if val, err := strconv.Atoi(blGlobalIntervalStr); err == nil && val > 0 {
		globalInterval = val
	}

	// Buat file blocklist default jika belum ada
	os.MkdirAll(filepath.Dir(BlocklistFile), 0755)
	if _, err := os.Stat(BlocklistFile); os.IsNotExist(err) {
		defaultBL := "# Format: NAME|INTERVAL(seconds)|MAX|URL\n" +
			"# If INTERVAL is 0, it uses RAF_BLOCKLIST_INTERVAL from settings.\n" +
			"SPAMDROP|86400|0|https://www.spamhaus.org/drop/drop.txt\n" +
			"DSHIELD|86400|0|https://www.dshield.org/block.txt\n"
		os.WriteFile(BlocklistFile, []byte(defaultBL), 0644)
	}

	// 2. Parse Blocklists Data (Hanya jika diaktifkan)
	ActiveBlocklists = []Blocklist{}
	if BlocklistEnabled {
		file, err := os.Open(BlocklistFile)
		if err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") { continue }
				
				parts := strings.Split(line, "|")
				if len(parts) >= 4 {
					interval := globalInterval // Gunakan interval global sebagai default
					if parsedInt, err := strconv.Atoi(parts[1]); err == nil && parsedInt > 0 {
						interval = parsedInt
					}
					
					ActiveBlocklists = append(ActiveBlocklists, Blocklist{
						Name:     strings.ToUpper(strings.TrimSpace(parts[0])),
						Interval: time.Duration(interval) * time.Second,
						URL:      strings.TrimSpace(parts[3]),
					})
				}
			}
			file.Close()
		}
	}

	// 3. Parse Country Codes (GeoIP)
	ActiveCCDeny = parseCC(ccDeny)
	ActiveCCAllow = parseCC(ccAllow)
	ActiveCCDenyPorts = parseCCPorts(ccDenyPorts)
	ActiveCCAllowPorts = parseCCPorts(ccAllowPorts)

	// Gabungkan semua kode negara unik agar IPSet-nya dibuat di Kernel
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

	// Support format pemisah pipa atau spasi: CN,RU:22,21|KP:80
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

// GenerateIpsetCommands dipanggil oleh firewall/ipset.go untuk membuat tabel hash kosong
func GenerateIpsetCommands(buffer *bytes.Buffer) {
	// Prepare IPsets for Country Codes (GeoIP)
	for _, cc := range ActiveCCDeny {
		buffer.WriteString(fmt.Sprintf("create cc_%s hash:net family inet hashsize 2048 maxelem 200000 -exist\nflush cc_%s\n", cc, cc))
	}
	for _, cc := range ActiveCCAllow {
		buffer.WriteString(fmt.Sprintf("create cc_%s hash:net family inet hashsize 2048 maxelem 200000 -exist\nflush cc_%s\n", cc, cc))
	}
	
	// Prepare IPsets for Blocklists
	if BlocklistEnabled {
		for _, bl := range ActiveBlocklists {
			buffer.WriteString(fmt.Sprintf("create bl_%s hash:net family inet hashsize 4096 maxelem 300000 -exist\nflush bl_%s\n", bl.Name, bl.Name))
		}
	}
}

// GenerateIptablesHooks dipanggil oleh firewall/engine.go untuk menghubungkan IPSet ke rule kernel
func GenerateIptablesHooks(buffer *bytes.Buffer) {
	// 1. Global Blocklists (Highest Priority Drop)
	if BlocklistEnabled {
		for _, bl := range ActiveBlocklists {
			buffer.WriteString(fmt.Sprintf("-A RAF_INPUT -m set --match-set bl_%s src -j DROP\n", bl.Name))
		}
	}

	// 2. GeoIP CC Deny & CC Deny Ports
	for _, cc := range ActiveCCDeny {
		if ports, exists := ActiveCCDenyPorts[cc]; exists {
			// Blokir Negara HANYA di Port Tertentu
			buffer.WriteString(fmt.Sprintf("-A RAF_DENY -m set --match-set cc_%s src -p tcp -m multiport --dports %s -j DROP\n", cc, ports))
			buffer.WriteString(fmt.Sprintf("-A RAF_DENY -m set --match-set cc_%s src -p udp -m multiport --dports %s -j DROP\n", cc, ports))
		} else {
			// Blokir Negara Secara Keseluruhan (Semua Port)
			buffer.WriteString(fmt.Sprintf("-A RAF_DENY -m set --match-set cc_%s src -j DROP\n", cc))
		}
	}

	// 3. GeoIP CC Allow & CC Allow Ports
	for _, cc := range ActiveCCAllow {
		if ports, exists := ActiveCCAllowPorts[cc]; exists {
			// Buka Port Tertentu secara Eksklusif untuk Negara
			buffer.WriteString(fmt.Sprintf("-A RAF_ALLOW -m set --match-set cc_%s src -p tcp -m multiport --dports %s -j ACCEPT\n", cc, ports))
			buffer.WriteString(fmt.Sprintf("-A RAF_ALLOW -m set --match-set cc_%s src -p udp -m multiport --dports %s -j ACCEPT\n", cc, ports))
		} else {
			// Buka Semua Akses untuk Negara (Bypass Firewall)
			buffer.WriteString(fmt.Sprintf("-A RAF_ALLOW -m set --match-set cc_%s src -j ACCEPT\n", cc))
		}
	}
}

// StartBackgroundWorkers memulai download Blocklist & meload GeoIP Zone secara asynchronous
func StartBackgroundWorkers() {
	// Load GeoIP (Country Zones) langsung di background
	if len(ActiveCCDeny) > 0 { go loadZonesToIpset(ActiveCCDeny) }
	if len(ActiveCCAllow) > 0 { go loadZonesToIpset(ActiveCCAllow) }

	// Mulai penjadwalan download Global Blocklists jika aktif
	if BlocklistEnabled {
		for _, bl := range ActiveBlocklists {
			go func(b Blocklist) {
				for {
					downloadAndInjectBlocklist(b)
					time.Sleep(b.Interval)
				}
			}(bl)
		}
	} else {
		utils.LogInfo("Ronin RAF Global Intel: Threat Blocklists auto-update is Disabled in config.")
	}
}

// loadZonesToIpset membaca file data negara (misal: /usr/local/ronin/lib/raf/zone/cn.zone)
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
			// Pastikan format valid IPv4/CIDR agar ipset tidak panic
			if ipv4Regex.MatchString(ip) {
				buffer.WriteString(fmt.Sprintf("add cc_%s %s -exist\n", cc, ip))
				count++
			}
		}
		file.Close()
	}

	if count > 0 {
		// Gunakan flag "-!" agar error minor duplikat diabaikan
		cmd := exec.Command("ipset", "-!", "restore")
		cmd.Stdin = bytes.NewReader(buffer.Bytes())
		if err := cmd.Run(); err == nil {
			utils.LogInfo("Ronin RAF GeoIP Intel: Successfully apply %d Country IP Blocks into memory.", count)
		} else {
			utils.LogError("Ronin RAF GeoIP Intel: Failed to inject IP blocks to Kernel.")
		}
	}
}

// downloadAndInjectBlocklist mengambil URL eksternal, regex semua IP, dan masukan ke kernel
func downloadAndInjectBlocklist(bl Blocklist) {
	utils.LogInfo("Ronin RAF Global Intel: Downloading Threat Feed [%s]...", bl.Name)

	// Batasi HTTP Request maksimal 30 detik agar tidak menyebabkan Memory Leak/Hang
	client := &http.Client{ Timeout: 30 * time.Second }

	resp, err := client.Get(bl.URL)
	if err != nil {
		utils.LogWarn("Ronin RAF Global Intel: Failed to fetch [%s] -> %v", bl.Name, err)
		return
	}
	defer resp.Body.Close()

	// Baca stream tanpa memenuhi batas kapasitas buffer memory Go
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024)) // Limit max 50MB
	if err != nil { return }

	ips := ipv4Regex.FindAllString(string(bodyBytes), -1)

	if len(ips) > 0 {
		var buffer bytes.Buffer
		buffer.WriteString(fmt.Sprintf("flush bl_%s\n", bl.Name)) // Bersihkan versi lama

		for _, ip := range ips {
			buffer.WriteString(fmt.Sprintf("add bl_%s %s -exist\n", bl.Name, ip))
		}

		// Inject ke IPSet dengan Flag kebal error
		cmd := exec.Command("ipset", "-!", "restore")
		cmd.Stdin = bytes.NewReader(buffer.Bytes())
		if err := cmd.Run(); err == nil {
			utils.LogInfo("Ronin RAF Global Intel: Feed [%s] updated! Loaded %d Malicious IPs.", bl.Name, len(ips))
		} else {
			utils.LogError("Ronin RAF Global Intel: Failed to apply [%s] to IPSet.", bl.Name)
		}
	} else {
		utils.LogWarn("Ronin RAF Global Intel: Feed [%s] returned 0 valid IPs.", bl.Name)
	}
}
