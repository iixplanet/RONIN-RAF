// file: lfd/tailer.go
package lfd

import (
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"raf/config"
	"raf/utils"
	"github.com/nxadm/tail"
)

// ==============================================================================
// 1. REGEX THREAT SIGNATURES (ANTI FALSE-POSITIVE)
// ==============================================================================
var (
	// SSHD: Deteksi Preauth, Invalid User, Maximum Auth, dan Failed Password
	RegexSSHD        = regexp.MustCompile(`(?i)(?:Failed password for|Invalid user|Connection closed by authenticating user|error: maximum authentication attempts exceeded|Disconnecting authenticating user|preauth).*?(?:from)\s+([0-9a-fA-F\.:]+)`)
	
	// FTPD: Menyatukan dukungan ProFTPd dan Pure-FTPd
	RegexFTPD        = regexp.MustCompile(`(?i)(?:pure-ftpd:.*?\(\?@([0-9a-fA-F\.:]+)\) \[WARNING\] Authentication failed|proftpd\[.*?\].*?([0-9a-fA-F\.:]+) .*?: Incorrect password)`)
	
	// EXIM / POSTFIX: Menangani authenticator failed, SASL login, dan Dovecot pop3/imap
	RegexExim        = regexp.MustCompile(`(?i)(?:authenticator failed|auth failed|Authentication failed|SASL LOGIN authentication failed).*?\[([0-9a-fA-F\.:]+)\]`)
	
	// CONTROL PANELS
	RegexCpanel      = regexp.MustCompile(`(?i)FAILED LOGIN.*?(?:from)?\s*([0-9a-fA-F\.:]+)`)
	RegexDirectAdmin = regexp.MustCompile(`(?i)'([0-9a-fA-F\.:]+)'\s+failed login attempt`)
	RegexPlesk       = regexp.MustCompile(`(?i)(?:plesk|failed login attempt).*?from IP ([0-9a-fA-F\.:]+)`)
	RegexCyberPanel  = regexp.MustCompile(`(?i)(?:Login failed|Invalid login).*?(?:IP:|from)\s*([0-9a-fA-F\.:]+)`)
	RegexAAPanel     = regexp.MustCompile(`(?i)(?:fail|invalid|Failed login).*?(?:IP:|from)\s*([0-9a-fA-F\.:]+)`)
	
	// WAF (Layer 7 Defense to Layer 4 Block)
	RegexModSec      = regexp.MustCompile(`(?i)ModSecurity: Access denied.*?\[client ([0-9a-fA-F\.:]+)\]`)
)

// ==============================================================================
// 2. LOG PARSING ENGINE
// ==============================================================================

// parseLogLine mengekstrak log, memvalidasi IP, dan menambahkan Strike
func parseLogLine(line, service string, maxLimit int) {
	// Fitur Panic Recovery: Memastikan daemon tidak pernah crash jika ada regex anomali
	defer func() {
		if r := recover(); r != nil {
			utils.LogError("Recovered from panic in LFD Regex parser: %v", r)
		}
	}()

	var match []string
	switch service {
	case "SSHD": match = RegexSSHD.FindStringSubmatch(line)
	case "FTPD": match = RegexFTPD.FindStringSubmatch(line)
	case "EXIM": match = RegexExim.FindStringSubmatch(line)
	case "CPANEL": match = RegexCpanel.FindStringSubmatch(line)
	case "DIRECTADMIN": match = RegexDirectAdmin.FindStringSubmatch(line)
	case "PLESK": match = RegexPlesk.FindStringSubmatch(line)
	case "CYBERPANEL": match = RegexCyberPanel.FindStringSubmatch(line)
	case "AAPANEL": match = RegexAAPanel.FindStringSubmatch(line)
	case "MODSEC": match = RegexModSec.FindStringSubmatch(line)
	}

	if len(match) > 1 {
		var rawIP string
		// Loop capture group untuk menemukan grup mana yang terisi IP
		for i := 1; i < len(match); i++ {
			if match[i] != "" { 
				rawIP = match[i]
				break 
			}
		}

		if rawIP != "" {
			rawIP = strings.TrimSpace(rawIP)
			
			// === VALIDASI LAPIS KEDUA (DOUBLE VALIDATION) ===
			// Memastikan bahwa string yang ditangkap benar-benar IP yang valid, bukan versi teks.
			if net.ParseIP(rawIP) == nil {
				return // Abaikan (False Positive berhasil ditangkal)
			}
			
			utils.LogWarn("STRIKE ALARM: IP %s failed %s authentication.", rawIP, service)
			AddStrike(rawIP, service, maxLimit)
		}
	}
}

// tailFile membaca log menggunakan Inotify/Polling (Event-Driven, Low CPU)
func tailFile(filePath, service string, maxLimit int) {
	t, err := tail.TailFile(filePath, tail.Config{
		Follow:    true,
		ReOpen:    true,  // Penting: Melanjutkan pembacaan jika log di-rotate oleh OS (logrotate)
		MustExist: false, // Penting: Menunggu file dibuat jika belum ada
		Poll:      true,  // Fallback aman untuk beberapa filesystem yang Inotify-nya mati
		Location:  &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END}, // Baca dari ujung bawah
	})
	
	if err != nil {
		utils.LogError("Failed to hook LFD to %s: %v", filePath, err)
		return
	}

	utils.LogInfo("LFD WATCHER: Active on %s [Target: %s | Limit: %d]", filePath, service, maxLimit)
	
	// Loop berjalan secara asinkron tanpa memblokir thread utama
	for line := range t.Lines {
		if line.Err != nil { continue }
		// Kirim ke goroutine agar pembacaan log selanjutnya tidak terhambat (Non-Blocking)
		go parseLogLine(line.Text, service, maxLimit)
	}
}

// ==============================================================================
// 3. MULTI-OS PATH RESOLVER
// ==============================================================================

// findLogPath mencari eksistensi file log di berbagai direktori standar OS (RHEL/Ubuntu/Debian)
func findLogPath(candidates []string) string {
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil { 
			return p 
		}
	}
	// Jika tidak ada yang ditemukan, kembalikan array pertama.
	// Library 'tail' akan menggunakan fitur MustExist: false untuk menunggu file tersebut dibuat.
	return candidates[0] 
}

// ==============================================================================
// 4. LFD ENGINE ORCHESTRATOR
// ==============================================================================

// StartLFDEngine merakit dan menjalankan seluruh pekerja LFD
func StartLFDEngine() {
	config.CoreData.Mutex.RLock()
	lfdEnabled := config.CoreData.Config["RAF_LF_DAEMON"]
	
	// Membaca batas (limits) dari file Konfigurasi
	limits := map[string]string{
		"SSHD":        config.CoreData.Config["RAF_LF_SSHD"],
		"FTPD":        config.CoreData.Config["RAF_LF_FTPD"],
		"EXIM":        config.CoreData.Config["RAF_LF_EXIM"],
		"CPANEL":      config.CoreData.Config["RAF_LF_CPANEL"],
		"DIRECTADMIN": config.CoreData.Config["RAF_LF_DIRECTADMIN"],
		"PLESK":       config.CoreData.Config["RAF_LF_PLESK"],
		"CYBERPANEL":  config.CoreData.Config["RAF_LF_CYBERPANEL"],
		"AAPANEL":     config.CoreData.Config["RAF_LF_AAPANEL"],
		"MODSEC":      config.CoreData.Config["RAF_LF_MODSEC"],
	}
	config.CoreData.Mutex.RUnlock()

	// Jika master switch LFD dimatikan, hentikan inisialisasi
	if lfdEnabled != "1" { 
		utils.LogInfo("LFD Engine is globally disabled in configuration.")
		return 
	}

	// Nyalakan Background Memory Manager
	go InitTempBans()
	go TempBanManager()
	go CleanupStrikes()

	// Eksekusi Log Tailers
	for svc, limitStr := range limits {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit <= 0 { 
			continue // Skip monitoring jika limit bernilai 0 atau tidak diset
		}

		var logPath string
		switch svc {
		case "SSHD": 
			logPath = findLogPath([]string{"/var/log/secure", "/var/log/auth.log"})
		case "FTPD": 
			logPath = findLogPath([]string{"/var/log/messages", "/var/log/syslog", "/var/log/proftpd/proftpd.log", "/var/log/pure-ftpd/pure-ftpd.log"})
		case "EXIM": 
			logPath = findLogPath([]string{"/var/log/exim_mainlog", "/var/log/exim4/mainlog", "/var/log/maillog"})
		case "CPANEL": 
			logPath = "/usr/local/cpanel/logs/login_log"
		case "DIRECTADMIN": 
			logPath = "/var/log/directadmin/login.log"
		case "PLESK": 
			logPath = findLogPath([]string{"/var/log/plesk/panel.log", "/var/log/sw-cp-server/error_log"})
		case "CYBERPANEL": 
			logPath = findLogPath([]string{"/usr/local/lsws/logs/error.log", "/home/cyberpanel/error-logs.txt"})
		case "AAPANEL": 
			logPath = findLogPath([]string{"/www/server/panel/logs/error.log", "/www/server/panel/logs/request/error_log"})
		case "MODSEC": 
			logPath = findLogPath([]string{"/var/log/modsec_audit.log", "/var/log/apache2/modsec_audit.log", "/var/log/httpd/modsec_audit.log"})
		}
		
		// Spawn Goroutine untuk masing-masing service
		go tailFile(logPath, svc, limit)
	}
}
