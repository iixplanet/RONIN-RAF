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
	
	// Ultra-Precise IPv4 & CIDR Regex
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

func downloadZoneFile(cc string) error {
	os.MkdirAll(ZoneDir, 0755)
	url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", strings.ToLower(cc))
	utils.LogInfo("GeoIP Intel: Fetching remote database for country [%s]...", cc)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil { return err }
	
	// Gunakan User-Agent Standard Browser agar tidak diblok oleh Cloudflare/IPDeny
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(req)
	
	// Perbaikan BUG FATAL: Cek error sebelum memanggil resp.StatusCode
	if err != nil {
		return fmt.Errorf("network connection error: %v", err)
	}
	defer resp.Body.Close()

	// Jika status bukan 200 OK, batalkan pembuatan file
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP Blocked/Failed. Status: %d", resp.StatusCode)
	}

	path := filepath.Join(ZoneDir, strings.ToLower(cc)+".zone")
	out, err := os.Create(path)
	if err != nil { return err }
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func loadZonesToIpset(ccList []string) {
	// Proteksi Global Panic Recovery khusus untuk thread ini
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
		// Eksekusi download jika file tidak ada atau ukurannya 0 byte (rusak)
		if os.IsNotExist(errStat) || (errStat == nil && info.Size() < 50) {
			if errDL := downloadZoneFile(cc); errDL != nil {
				utils.LogError("GeoIP Intel: Failed to download zone [%s]: %v", cc, errDL)
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
	} else {
		utils.LogWarn("GeoIP Intel: Found 0 valid IPs. Database might be empty or corrupted.")
	}
}

func downloadAndInjectBlocklist(bl Blocklist) {
	// Proteksi Global Panic Recovery
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
	
	// Perbaikan BUG FATAL: Cek error sebelum memanggil resp.StatusCode
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
