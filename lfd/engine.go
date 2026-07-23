// file: lfd/engine.go
package lfd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"raf/config"
	"raf/firewall"
	"raf/utils"
)

const TempBanFile = "/usr/local/ronin/lib/raf/raf.tempban"

type StrikeRecord struct {
	Count      int
	LastStrike time.Time
}

type TempBanRecord struct {
	IP        string
	ExpiresAt time.Time
	Reason    string
}

var (
	StrikeMap      = make(map[string]map[string]*StrikeRecord)
	TempBans       = make(map[string]*TempBanRecord)
	TempBanHistory = make(map[string]int)
	EngineMutex    sync.Mutex
)

func InitTempBans() {
	os.MkdirAll(filepath.Dir(TempBanFile), 0755)
	file, err := os.Open(TempBanFile)
	if err != nil { return }
	defer file.Close()

	now := time.Now()
	scanner := bufio.NewScanner(file)
	EngineMutex.Lock()
	defer EngineMutex.Unlock()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" { continue }
		parts := strings.SplitN(line, "|", 3)
		if len(parts) == 3 {
			ip := parts[0]
			var expInt int64
			fmt.Sscanf(parts[1], "%d", &expInt)
			expTime := time.Unix(expInt, 0)
			if expTime.After(now) {
				TempBans[ip] = &TempBanRecord{ IP: ip, ExpiresAt: expTime, Reason: parts[2] }
				go firewall.DynamicBan(ip)
			}
		}
	}
}

func SaveTempBans() {
	EngineMutex.Lock()
	defer EngineMutex.Unlock()
	file, err := os.OpenFile(TempBanFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil { return }
	defer file.Close()
	for _, record := range TempBans {
		file.WriteString(fmt.Sprintf("%s|%d|%s\n", record.IP, record.ExpiresAt.Unix(), record.Reason))
	}
}

func AddStrike(ip, service string, maxLimit int) {
	config.CoreData.Mutex.RLock()
	isSafe := false
	for _, safeIP := range config.CoreData.AllowList4 { if ip == safeIP { isSafe = true; break } }
	for _, safeIP := range config.CoreData.AllowList6 { if ip == safeIP { isSafe = true; break } }
	config.CoreData.Mutex.RUnlock()

	if isSafe { return }

	EngineMutex.Lock()
	if StrikeMap[ip] == nil { StrikeMap[ip] = make(map[string]*StrikeRecord) }
	if StrikeMap[ip][service] == nil { StrikeMap[ip][service] = &StrikeRecord{Count: 0, LastStrike: time.Now()} }

	record := StrikeMap[ip][service]
	record.Count++
	record.LastStrike = time.Now()
	currentCount := record.Count
	EngineMutex.Unlock()

	if currentCount >= maxLimit {
		config.CoreData.Mutex.RLock()
		durStr := config.CoreData.Config["RAF_LF_TEMP_BAN_TIME"]
		triggerStr := config.CoreData.Config["RAF_LF_PERM_BAN_TRIGGER"]
		config.CoreData.Mutex.RUnlock()

		duration := 3600
		trigger := 4
		if d, err := strconv.Atoi(durStr); err == nil && d > 0 { duration = d }
		if t, err := strconv.Atoi(triggerStr); err == nil && t > 0 { trigger = t }

		EngineMutex.Lock()
		TempBanHistory[ip]++
		histCount := TempBanHistory[ip]
		EngineMutex.Unlock()

		reason := fmt.Sprintf("%s Bruteforce Detected (%d strikes)", service, currentCount)

		if histCount >= trigger {
			utils.LogWarn("LFD ESCALATION: %s hit Temp Ban %d times. Converted to Permanent Ban.", ip, histCount)
			appendToDeny(ip, "LFD Escalation: Repeat Offender ("+service+")")
			firewall.DynamicBan(ip)
			
			EngineMutex.Lock()
			delete(TempBans, ip)
			delete(StrikeMap, ip)
			EngineMutex.Unlock()
			SaveTempBans()
			return
		}

		ExecuteBan(ip, reason, duration)
		EngineMutex.Lock()
		delete(StrikeMap, ip)
		EngineMutex.Unlock()
	}
}

func appendToDeny(ip, reason string) {
	f, _ := os.OpenFile(config.DenyFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	defer f.Close()
	f.WriteString(fmt.Sprintf("%s # %s\n", ip, reason))
}

func ExecuteBan(ip, reason string, durationSeconds int) {
	EngineMutex.Lock()
	if _, exists := TempBans[ip]; exists {
		EngineMutex.Unlock()
		return
	}
	TempBans[ip] = &TempBanRecord{
		IP:        ip,
		ExpiresAt: time.Now().Add(time.Duration(durationSeconds) * time.Second),
		Reason:    reason,
	}
	EngineMutex.Unlock()

	SaveTempBans()
	firewall.DynamicBan(ip)
	utils.LogWarn("LFD ENFORCEMENT: %s Banned for %d secs. Reason: %s", ip, durationSeconds, reason)
}

func ExecuteUnban(ip string) {
	EngineMutex.Lock()
	if _, exists := TempBans[ip]; exists { delete(TempBans, ip) }
	EngineMutex.Unlock()
	SaveTempBans()
	firewall.DynamicUnban(ip)
	utils.LogInfo("LFD MANUAL UNBAN: %s removed by Admin Command.", ip)
}

// Fungsi Baru untuk System Override Clear All Temp Bans
func FlushAllTempBans() {
	EngineMutex.Lock()
	for ip := range TempBans {
		go firewall.DynamicUnban(ip)
		delete(TempBans, ip)
	}
	EngineMutex.Unlock()
	SaveTempBans()
	utils.LogWarn("ADMIN ACTION: All LFD Temporary Bans have been flushed.")
}

func TempBanManager() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		now := time.Now()
		unbanned := false

		EngineMutex.Lock()
		for ip, record := range TempBans {
			if now.After(record.ExpiresAt) {
				delete(TempBans, ip)
				go firewall.DynamicUnban(ip)
				utils.LogInfo("LFD AUTO-UNBAN: Temporary ban expired for %s", ip)
				unbanned = true
			}
		}
		EngineMutex.Unlock()

		if unbanned { SaveTempBans() }
	}
}

func CleanupStrikes() {
	ticker := time.NewTicker(15 * time.Minute)
	for range ticker.C {
		now := time.Now()

		config.CoreData.Mutex.RLock()
		intervalStr := config.CoreData.Config["RAF_LF_INTERVAL"]
		config.CoreData.Mutex.RUnlock()

		interval := 3600
		if i, err := strconv.Atoi(intervalStr); err == nil && i > 0 { interval = i }
		forgiveDur := time.Duration(interval) * time.Second

		EngineMutex.Lock()
		for ip, services := range StrikeMap {
			for svc, record := range services {
				if now.Sub(record.LastStrike) > forgiveDur {
					delete(services, svc)
				}
			}
			if len(services) == 0 { delete(StrikeMap, ip) }
		}
		EngineMutex.Unlock()
	}
}
