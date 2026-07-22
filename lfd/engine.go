// file: lfd/engine.go
package lfd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
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
	StrikeMap   = make(map[string]map[string]*StrikeRecord) // map[IP]map[Service]Record
	TempBans    = make(map[string]*TempBanRecord)           // map[IP]TempBan
	EngineMutex sync.Mutex
)

// InitTempBans membaca blokiran sementara yang tersisa dari disk saat RAF di-restart
func InitTempBans() {
	os.MkdirAll(filepath.Dir(TempBanFile), 0755)
	file, err := os.Open(TempBanFile)
	if err != nil {
		return // File belum ada, abaikan
	}
	defer file.Close()

	now := time.Now()
	scanner := bufio.NewScanner(file)
	
	EngineMutex.Lock()
	defer EngineMutex.Unlock()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" { continue }

		// Format: IP|UnixExpirationTimestamp|Reason
		parts := strings.SplitN(line, "|", 3)
		if len(parts) == 3 {
			ip := parts[0]
			var expInt int64
			fmt.Sscanf(parts[1], "%d", &expInt)
			expTime := time.Unix(expInt, 0)

			// Jika belum expired, masukkan ke memori
			if expTime.After(now) {
				TempBans[ip] = &TempBanRecord{
					IP:        ip,
					ExpiresAt: expTime,
					Reason:    parts[2],
				}
				// Pastikan tetap ada di ipset
				go firewall.DynamicBan(ip)
			}
		}
	}
}

// SaveTempBans menyimpan state memori ke disk
func SaveTempBans() {
	EngineMutex.Lock()
	defer EngineMutex.Unlock()

	file, err := os.OpenFile(TempBanFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil { return }
	defer file.Close()

	for _, record := range TempBans {
		line := fmt.Sprintf("%s|%d|%s\n", record.IP, record.ExpiresAt.Unix(), record.Reason)
		file.WriteString(line)
	}
}

// AddStrike menambah poin pelanggaran. Jika melebihi limit, IP diblokir sementara (Default: 3600 detik/1 jam)
func AddStrike(ip, service string, maxLimit int) {
	// 1. Cek Anti-Lockout
	config.CoreData.Mutex.RLock()
	isSafe := false
	for _, safeIP := range config.CoreData.AllowList4 {
		if ip == safeIP { isSafe = true; break }
	}
	for _, safeIP := range config.CoreData.AllowList6 {
		if ip == safeIP { isSafe = true; break }
	}
	config.CoreData.Mutex.RUnlock()

	if isSafe {
		utils.LogWarn("LFD AVERTED: %s Bruteforce detected, but IP is in Whitelist/Local.", ip)
		return
	}

	EngineMutex.Lock()
	if StrikeMap[ip] == nil { StrikeMap[ip] = make(map[string]*StrikeRecord) }
	if StrikeMap[ip][service] == nil { StrikeMap[ip][service] = &StrikeRecord{Count: 0, LastStrike: time.Now()} }

	record := StrikeMap[ip][service]
	record.Count++
	record.LastStrike = time.Now()
	currentCount := record.Count
	EngineMutex.Unlock()

	if currentCount >= maxLimit {
		reason := fmt.Sprintf("%s Bruteforce Detected (%d strikes)", service, currentCount)
		ExecuteBan(ip, reason, 3600) // Default 1 jam ban (3600 detik)
		
		// Reset strike setelah diblokir
		EngineMutex.Lock()
		delete(StrikeMap, ip)
		EngineMutex.Unlock()
	}
}

// ExecuteBan menembakkan eksekusi pemblokiran
func ExecuteBan(ip, reason string, durationSeconds int) {
	EngineMutex.Lock()
	// Mencegah block ganda
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

// TempBanManager berjalan di background mengecek IP yang masa hukumannya sudah habis
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

		if unbanned {
			SaveTempBans()
		}
	}
}

// CleanupStrikes membersihkan strike usang (1 jam tidak diulangi = dimaafkan)
func CleanupStrikes() {
	ticker := time.NewTicker(15 * time.Minute)
	for range ticker.C {
		now := time.Now()
		EngineMutex.Lock()
		for ip, services := range StrikeMap {
			for svc, record := range services {
				if now.Sub(record.LastStrike) > 1*time.Hour {
					delete(services, svc)
				}
			}
			if len(services) == 0 { delete(StrikeMap, ip) }
		}
		EngineMutex.Unlock()
	}
}