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
	
	// Ultra-Precise IPv4 & CIDR Regex (Tahan terhadap string kotor dari Github)
	ipv4Regex = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[1-2]?[0-9]|3[0-2]))?\b`)
)

func InitAndParse() {
	if err := os.MkdirAll(ZoneDir, 0755); err != nil {
		utils.LogError("Failed to create Zone Directory: %v", err)
	}

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

	BlocklistEnabled = (blEnabledStr == "1" || strings.ToLower(blEnabledStr) == "true")
	globalInterval := 86400 
	if val, err := strconv.Atoi(blGlobalIntervalStr); err == nil && val > 0 {
		globalInterval = val
	}

	ActiveBlocklists = []Blocklist{}
	if BlocklistEnabled {
		if urlSpamdrop != "" { ActiveBlocklists = append(ActiveBlocklists, Blocklist{Name: "SPAMDROP", Interval: time.Duration(globalInterval) * time.Second, URL: urlSpamdrop}) }
		if urlDshield != "" { ActiveBlocklists = append(ActiveBlocklists, Blocklist{Name: "DSHIELD", Interval: time.Duration(globalInterval) * time.Second, URL: urlDshield}) }
		if urlCustom != "" { ActiveBlocklists = append(ActiveBlocklists, Blocklist{Name: "CUSTOM_INTEL", Interval: time.Duration(globalInterval) * time.Second, URL: urlCustom}) }
	}

	ActiveCCDeny = parseCC(ccDeny)
	ActiveCCAllow = parseCC(ccAllow)
	ActiveCCDenyPorts = parseCCPorts(ccDenyPorts)
	ActiveCCAllowPorts = parseCCPorts(ccAllowPorts)

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

func GenerateIpsetCommands(buffer *bytes.Buffer) {
	for _, cc := range ActiveCCDeny {
		buffer.WriteString(fmt.Sprintf("create cc_%s hash:net family inet hashsize 2048 maxelem 200000 -exist\nflush cc_%s\n", cc, cc))
	}
	for _, cc := range ActiveCCAllow {
		buffer.WriteString(fmt.Sprintf("create cc_%s hash:net family inet hashsize 2048 maxelem 200000 -exist\nflush cc_%s\n", cc, cc))
	}
	if BlocklistEnabled {
		for _, bl := range ActiveBlocklists {
			buffer.WriteString(fmt.Sprintf("create bl_%s hash:net family inet hashsize 8192 maxelem 500000 -exist\n", bl.Name))
		}
	}
}

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

// MULTI-MIRROR AUTO DOWNLOADER (Menggunakan URL Valid Terbaru)
func downloadZoneFile(cc string) error {
	os.MkdirAll(ZoneDir, 0755)
	ccLower := strings.ToLower(cc)
	ccUpper := strings.ToUpper(cc)
	
	mirrors := []string{
		// Mirror 1: IPVerse Github (Tercepat & Paling Update)
		fmt.Sprintf("https://raw.githubusercontent.com/ipverse/country-ip-blocks/refs/heads/master/country/%s/ipv4-aggregated.txt", ccLower),
		// Mirror 2: IPDeny (Sering kena Rate Limit/Timeout, jadi posisi ke-2)
		fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", ccLower),
	}

	var lastErr error
	for i, url := range mirrors {
		utils.LogInfo("GeoIP Intel: Fetching Mirror %d for country [%s]...", i+1, ccUpper)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil { 
			lastErr = err
			continue 
		}
		
		// Menyamar sebagai Browser Asli agar tidak di-blok oleh Cloudflare
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/plain,text/html,*/*")

		client := &http.Client{Timeout: 20 * time.Second}
		resp, err := client.Do(req)
		
		if err != nil {
			utils.LogWarn("GeoIP Intel: Mirror %d network failure. Trying next...", i+1)
			lastErr = fmt.Errorf("network error: %v", err)
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			utils.LogWarn("GeoIP Intel: Mirror %d returned HTTP %d. Trying next...", i+1, resp.StatusCode)
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		path := filepath.Join(ZoneDir, ccLower+".zone")
		out, err := os.Create(path)
		if err != nil { 
			resp.Body.Close()
			return err 
		}

		_, err = io.Copy(out, resp.Body)
		out.Close()
		resp.Body.Close()

		if err == nil {
			utils.LogInfo("GeoIP Intel: Successfully downloaded zone [%s] from Mirror %d", ccUpper, i+1)
			return nil 
		}
		lastErr = err
	}

	return fmt.Errorf("All mirrors failed. Last error: %v", lastErr)
}

func loadZonesToIpset(ccList []string) {
	defer func() {
		if r := recover(); r != nil {
			utils.LogError("FATAL: Panic recovered in GeoIP loader: %v", r)
		}
	}()

	var buffer bytes.Buffer
	count := 0

	for _, cc := range ccList {
		path := filepath.Join(ZoneDir, strings.ToLower(cc)+".zone")
		
		info, errStat := os.Stat(path)
		// Jika ukuran file kurang dari 50 bytes (rusak/kosong), paksa download ulang
		if os.IsNotExist(errStat) || (errStat == nil && info.Size() < 50) {
			if errDL := downloadZoneFile(cc); errDL != nil {
				utils.LogError("GeoIP Intel: Total failure downloading zone [%s]: %v", cc, errDL)
				continue
			}
		}

		file, err := os.Open(path)
		if err != nil {
			utils.LogWarn("GeoIP Zone file is unreadable: %s", path)
			continue
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Abaikan baris kosong atau komentar bawaan list Github (#)
			if line == "" || strings.HasPrefix(line, "#") { continue }
			
			// Ambil IP murni untuk membuang teks-teks sisa header
			ip := ipv4Regex.FindString(line)
			if ip != "" {
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
	} else {
		utils.LogWarn("GeoIP Intel: Found 0 valid IPs. Database might be empty or corrupted.")
	}
}

func downloadAndInjectBlocklist(bl Blocklist) {
	defer func() {
		if r := recover(); r != nil {
			utils.LogError("FATAL: Panic recovered in Blocklist loader: %v", r)
		}
	}()

	utils.LogInfo("Global Intel: Downloading Threat Feed [%s]...", bl.Name)

	req, err := http.NewRequest("GET", bl.URL, nil)
	if err != nil { return }
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	client := &http.Client{ Timeout: 45 * time.Second }
	resp, err := client.Do(req)
	
	if err != nil {
		utils.LogWarn("Global Intel: Network error fetching [%s]: %v", bl.Name, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		utils.LogWarn("Global Intel: HTTP %d fetching [%s] -> Retaining old IP data.", resp.StatusCode, bl.Name)
		return
	}

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
