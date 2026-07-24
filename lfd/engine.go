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

// StrikeRecord menyimpan rekam jejak gagal login (Auth Failures)
type StrikeRecord struct {
	Count      int
	LastStrike time.Time
}

// TempBanRecord menyimpan profil IP yang sedang dihukum sementara
type TempBanRecord struct {
	IP        string
	ExpiresAt time.Time
	Reason    string
}

var (
	StrikeMap      = make(map[string]map[string]*StrikeRecord) // Memori ancaman real-time
	TempBans       = make(map[string]*TempBanRecord)           // Memori hukuman sementara
	TempBanHistory = make(map[string]int)                      // Mencatat berapa kali IP masuk Temp Ban
	EngineMutex    sync.Mutex                                  // Thread-safe lock
)

// InitTempBans membaca hukuman sementara yang belum expired dari disk saat RAF di-restart
func InitTempBans() {
	os.MkdirAll(filepath.Dir(TempBanFile), 0755)
	file, err := os.Open(TempBanFile)
	if err != nil { return } // File belum ada, aman diabaikan
	defer file.Close()

	now := time.Now()
	scanner := bufio.NewScanner(file)
	
	EngineMutex.Lock()
	defer EngineMutex.Unlock()

	utils.LogDebug("INFO: RAF LFD INIT: Restoring active temporary bans from disk state.")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" { continue }
		
		// Format: IP|UnixTimestamp|Reason
		parts := strings.SplitN(line, "|", 3)
		if len(parts) == 3 {
			ip := parts[0]
			var expInt int64
			fmt.Sscanf(parts[1], "%d", &expInt)
			expTime := time.Unix(expInt, 0)
			
			// Jika belum expired, masukkan ke memori dan pasang ulang di Ipset
			if expTime.After(now) {
				TempBans[ip] = &TempBanRecord{ IP: ip, ExpiresAt: expTime, Reason: parts[2] }
				go firewall.DynamicAdd(ip, "DENY")
			}
		}
	}
}

// SaveTempBans menyimpan memori hukuman ke dalam file disk (Crash Recovery)
func SaveTempBans() {
	EngineMutex.Lock()
	defer EngineMutex.Unlock()
	
	file, err := os.OpenFile(TempBanFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil { return }
	defer file.Close()
	
	for _, record := range TempBans {
		file.WriteString(fmt.Sprintf("%s|%d|%s\n", record.IP, record.ExpiresAt.Unix(), record.Reason))
	}
	
	utils.LogDebug("RAF LFD SYNC: Saved %d active temporary bans to disk.", len(TempBans))
}

// EnforceTempBanLimit memastikan RAM tidak penuh. Jika mencapai batas, IP paling cepat expired akan dibuang.
func EnforceTempBanLimit() {
	config.CoreData.Mutex.RLock()
	limitStr := config.CoreData.Config["RAF_TEMP_IP_LIMIT"]
	config.CoreData.Mutex.RUnlock()

	limit := 1000 // Default 1000 IP
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 { limit = l }

	EngineMutex.Lock()
	defer EngineMutex.Unlock()

	// Looping pembuangan IP sampai ukuran map kembali ke batas normal
	for len(TempBans) > limit {
		var soonest string
		var minExp time.Time
		first := true

		// Cari IP yang paling cepat masa hukumannya habis
		for ip, rec := range TempBans {
			if first || rec.ExpiresAt.Before(minExp) {
				soonest = ip
				minExp = rec.ExpiresAt
				first = false
			}
		}

		if soonest != "" {
			delete(TempBans, soonest)
			go firewall.DynamicDel(soonest, "DENY") // Cabut dari Kernel
			utils.LogWarn("RAF LIMIT PRUNE: %s removed from Temp Ban (Exceeds %d Max Limit)", soonest, limit)
		}
	}
}

// escalateToPermBan menangani konversi hukuman sementara menjadi permanen
func escalateToPermBan(ip, reason string) {
	// 1. Ambil batasan limit dari konfigurasi
	config.CoreData.Mutex.RLock()
	limitStr := config.CoreData.Config["RAF_DENY_IP_LIMIT"]
	config.CoreData.Mutex.RUnlock()

	limit := 2000 // Default 2000 IP
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 { limit = l }

	reason = strings.ReplaceAll(reason, "\n", " ")
	reason = strings.ReplaceAll(reason, "\r", "")

	// 2. Baca file Permanent Deny saat ini
	data, err := os.ReadFile(config.DenyFile)
	if err != nil {
		// File kosong/tidak ada, langsung buat
		f, _ := os.OpenFile(config.DenyFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		f.WriteString(fmt.Sprintf("%s # %s\n", ip, reason))
		f.Close()
		go firewall.DynamicAdd(ip, "DENY")
		return
	}

	// 3. Pruning Logika FIFO & EXACT MATCH (Pencegahan Duplikasi)
	lines := strings.Split(string(data), "\n")
	var ipLines []string
	var headerLines []string
	ipExists := false

	for _, line := range lines {
		clean := strings.TrimSpace(line)
		if clean == "" { continue }
		if strings.HasPrefix(clean, "#") { 
			headerLines = append(headerLines, line)
		} else { 
			// Evaluasi duplikasi dengan persisi string penuh (Exact Match)
			parts := strings.SplitN(clean, "#", 2)
			if strings.TrimSpace(parts[0]) == ip {
				ipExists = true
			}
			ipLines = append(ipLines, line) 
		}
	}

	// Jika IP sudah ada di daftar permanen, hentikan proses tulis file ganda
	if ipExists {
		utils.LogDebug("RAF LFD ESCALATION: IP %s already exists in Perm Deny List. Skipped duplication.", ip)
		return
	}

	// Buang IP terlama jika melebihi batas (Pruning)
	if len(ipLines) >= limit {
		diff := (len(ipLines) - limit) + 1
		pruned := ipLines[:diff]
		kept := ipLines[diff:]

		// Cabut IP yang dibuang dari Kernel
		for _, pLine := range pruned {
			parts := strings.SplitN(pLine, " ", 2)
			prunedIP := strings.TrimSpace(parts[0])
			go firewall.DynamicDel(prunedIP, "DENY")
			utils.LogWarn("RAF LIMIT PRUNE: %s removed from Perm Deny (Exceeds %d Max Limit)", prunedIP, limit)
		}

		var newContent []string
		newContent = append(newContent, headerLines...)
		newContent = append(newContent, kept...)
		os.WriteFile(config.DenyFile, []byte(strings.Join(newContent, "\n")+"\n"), 0644)
	}

	// 4. Tulis IP Baru dan Suntikkan ke Kernel
	f, _ := os.OpenFile(config.DenyFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	f.WriteString(fmt.Sprintf("%s # %s\n", ip, reason))
	f.Close()
	
	go firewall.DynamicAdd(ip, "DENY")
}

// AddStrike mencatat gagal login, menindak jika limit tercapai (Auth Failure Tracker)
func AddStrike(ip, service string, maxLimit int) {
	// 1. Cek Anti-Lockout (Whitelist & LFD Ignore)
	config.CoreData.Mutex.RLock()
	isSafe := false
	
	// Cek Perm Allow (Kebal Semua Aturan Firewall & LFD)
	for _, safeIP := range config.CoreData.AllowList4 { if ip == safeIP { isSafe = true; break } }
	for _, safeIP := range config.CoreData.AllowList6 { if ip == safeIP { isSafe = true; break } }
	
	// [FITUR LFD IGNORE] Cek file raf.ignore (Tetap tunduk pada firewall, tapi kebal dari LFD Blokir Gagal Login)
	if !isSafe {
		for _, safeIP := range config.CoreData.IgnoreList4 { if ip == safeIP { isSafe = true; break } }
		for _, safeIP := range config.CoreData.IgnoreList6 { if ip == safeIP { isSafe = true; break } }
	}
	config.CoreData.Mutex.RUnlock()

	if isSafe { 
		// Menggunakan istilah profesional
		utils.LogDebug("RAF LFD BYPASS: IP %s matched whitelist/ignore list. Auth failure dismissed.", ip)
		return 
	}

	// 2. Tambahkan Poin (Failed Attempt) dalam Mode Thread-Safe
	EngineMutex.Lock()
	if StrikeMap[ip] == nil { StrikeMap[ip] = make(map[string]*StrikeRecord) }
	if StrikeMap[ip][service] == nil { StrikeMap[ip][service] = &StrikeRecord{Count: 0, LastStrike: time.Now()} }

	record := StrikeMap[ip][service]
	record.Count++
	record.LastStrike = time.Now()
	currentCount := record.Count
	EngineMutex.Unlock()

	// Menggunakan istilah profesional
	utils.LogDebug("RAF LFD TRACKER: Memory recorded auth failure %d/%d for %s (Service: %s)", currentCount, maxLimit, ip, service)

	// 3. Jika Limit Tercapai, Eksekusi Hukuman
	if currentCount >= maxLimit {
		config.CoreData.Mutex.RLock()
		durStr := config.CoreData.Config["RAF_LF_TEMP_BAN_TIME"]
		triggerStr := config.CoreData.Config["RAF_LF_PERM_BAN_TRIGGER"]
		config.CoreData.Mutex.RUnlock()

		duration := 3600 // Default 1 Jam
		trigger := 4     // Default Pindah ke Permanen setelah 4x Temp Ban
		
		if d, err := strconv.Atoi(durStr); err == nil && d > 0 { duration = d }
		if t, err := strconv.Atoi(triggerStr); err == nil && t > 0 { trigger = t }

		EngineMutex.Lock()
		TempBanHistory[ip]++
		histCount := TempBanHistory[ip]
		EngineMutex.Unlock()

		// Menggunakan istilah profesional
		reason := fmt.Sprintf("%s Bruteforce Detected (%d failed attempts)", service, currentCount)

		// 4. ESKALASI PERMANEN
		if histCount >= trigger {
			utils.LogWarn("RAF LFD ESCALATION: %s hit Temp Ban %d times. Converted to Permanent Ban.", ip, histCount)
			
			escalateToPermBan(ip, "RAF LFD Escalation: Repeat Offender ("+service+")")
			
			// Bersihkan dari cache memori agar tidak bentrok
			EngineMutex.Lock()
			delete(TempBans, ip)
			delete(StrikeMap, ip)
			EngineMutex.Unlock()
			SaveTempBans()
			return
		}

		// 5. HUKUMAN SEMENTARA (Temp Ban)
		ExecuteBan(ip, reason, duration)
		
		EngineMutex.Lock()
		delete(StrikeMap, ip) // Reset counter untuk service ini
		EngineMutex.Unlock()
	}
}

// GetActiveFailures membaca memori RAM untuk dikirimkan ke Dashboard UI (Tab Live Auth Failures)
func GetActiveFailures() []map[string]interface{} {
	EngineMutex.Lock()
	defer EngineMutex.Unlock()

	var result []map[string]interface{}
	
	for ip, services := range StrikeMap {
		totalFailures := 0
		// Jumlahkan total gagal login dari berbagai service (SSH, FTP, dll) untuk IP tersebut
		for _, record := range services {
			totalFailures += record.Count
		}
		
		if totalFailures > 0 {
			result = append(result, map[string]interface{}{
				"ip":    ip,
				"count": totalFailures,
			})
		}
	}
	
	// Cegah return null JSON
	if result == nil {
		result = []map[string]interface{}{}
	}
	return result
}

// ExecuteBan menembakkan eksekusi pemblokiran sementara ke Ipset
func ExecuteBan(ip, reason string, durationSeconds int) {
	EngineMutex.Lock()
	// Mencegah double ban
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
	EnforceTempBanLimit() // Lakukan pruning jika memori lewat batas
	go firewall.DynamicAdd(ip, "DENY")
	
	utils.LogWarn("RAF LFD TEMPBLOCK: %s Temp Banned for %d secs. Reason: %s", ip, durationSeconds, reason)
}

// ExecuteUnban menghapus IP dari hukuman sementara sebelum waktunya (Atas Perintah Admin)
func ExecuteUnban(ip string) {
	EngineMutex.Lock()
	if _, exists := TempBans[ip]; exists { delete(TempBans, ip) }
	EngineMutex.Unlock()
	
	SaveTempBans()
	go firewall.DynamicDel(ip, "DENY")
	utils.LogInfo("RAF LFD MANUAL UNBAN: %s removed by Administrator.", ip)
}

// FlushAllTempBans menyapu bersih seluruh IP dari daftar Temp Ban
func FlushAllTempBans() {
	EngineMutex.Lock()
	for ip := range TempBans { 
		go firewall.DynamicDel(ip, "DENY")
		delete(TempBans, ip) 
	}
	EngineMutex.Unlock()
	
	SaveTempBans()
	utils.LogWarn("ADMIN ACTION: All RAF LFD Temporary Bans have been flushed successfully.")
}

// TempBanManager Ticker yang berjalan di background mengecek IP expired
func TempBanManager() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		now := time.Now()
		unbanned := false

		EngineMutex.Lock()
		for ip, record := range TempBans {
			if now.After(record.ExpiresAt) {
				delete(TempBans, ip)
				go firewall.DynamicDel(ip, "DENY")
				utils.LogInfo("RAF LFD AUTO-UNBAN: Temporary ban duration expired for %s", ip)
				unbanned = true
			}
		}
		EngineMutex.Unlock()

		if unbanned { SaveTempBans() }
	}
}

// CleanupStrikes membersihkan strike usang agar IP yang lama berhenti tidak dihukum
func CleanupStrikes() {
	ticker := time.NewTicker(15 * time.Minute)
	for range ticker.C {
		now := time.Now()

		config.CoreData.Mutex.RLock()
		intervalStr := config.CoreData.Config["RAF_LF_INTERVAL"]
		config.CoreData.Mutex.RUnlock()

		interval := 3600 // Default memori strike: 1 jam
		if i, err := strconv.Atoi(intervalStr); err == nil && i > 0 { interval = i }
		forgiveDur := time.Duration(interval) * time.Second

		EngineMutex.Lock()
		clearedAny := false
		for ip, services := range StrikeMap {
			for svc, record := range services {
				// Jika jarak dari strike terakhir sudah melebihi RAF_LF_INTERVAL, bersihkan.
				if now.Sub(record.LastStrike) > forgiveDur {
					delete(services, svc)
					clearedAny = true
					// Menggunakan istilah profesional
					utils.LogDebug("RAF LFD MEMORY: Cleanup auth failures for %s on service %s (Time elapsed)", ip, svc)
				}
			}
			// Hapus record IP utama jika semua service sudah dibersihkan
			if len(services) == 0 { delete(StrikeMap, ip) }
		}
		EngineMutex.Unlock()

		// Konfirmasi Cycle Cleanup
		if clearedAny {
			utils.LogDebug("RAF LFD MEMORY: Auth failure cleanup cycle completed.")
		}
	}
}
