// file: config/parser.go
package config

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"raf/utils" // Ubah "raf" sesuaikan dengan nama module go.mod Anda
)

// file: config/parser.go (Tambahkan di bawah blok import)
const (
	AllowFile = "/usr/local/ronin/lib/raf/raf.allow"
	DenyFile  = "/usr/local/ronin/lib/raf/raf.deny"
)

type RAFData struct {
	Config     map[string]string
	AllowList4 []string
	AllowList6 []string
	DenyList4  []string
	DenyList6  []string
	Mutex      sync.RWMutex
}

var CoreData = RAFData{
	Config: make(map[string]string),
}

func LoadAll(configPath, allowPath, denyPath string) {
	CoreData.Mutex.Lock()
	defer CoreData.Mutex.Unlock()

	// 1. Load Main Config
	CoreData.Config = make(map[string]string)
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
				val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				CoreData.Config[key] = val
			}
		}
		file.Close()
	}

	// 2. Clear old lists
	CoreData.AllowList4, CoreData.AllowList6 = []string{}, []string{}
	CoreData.DenyList4, CoreData.DenyList6 = []string{}, []string{}

	// 3. Inject Anti-Lockout (Local Server IPs) into AllowList
	localIPs := utils.GetLocalIPs()
	for _, ip := range localIPs {
		if utils.CheckIPType(ip) == "4" {
			CoreData.AllowList4 = append(CoreData.AllowList4, ip)
		} else if utils.CheckIPType(ip) == "6" {
			CoreData.AllowList6 = append(CoreData.AllowList6, ip)
		}
	}

	// 4. Parse Allow File
	parseListFile(allowPath, &CoreData.AllowList4, &CoreData.AllowList6)
	
	// 5. Parse Deny File
	parseListFile(denyPath, &CoreData.DenyList4, &CoreData.DenyList6)
}

func parseListFile(path string, list4, list6 *[]string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Buang komentar di sebelah IP (misal: 192.168.1.1 # Blocked)
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		ipType := utils.CheckIPType(line)
		if ipType == "4" {
			*list4 = append(*list4, line)
		} else if ipType == "6" {
			*list6 = append(*list6, line)
		}
	}
}
