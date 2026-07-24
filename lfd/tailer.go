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
// 1. ENTERPRISE THREAT SIGNATURES (ANTI FALSE-POSITIVE & NAT AWARE)
// ==============================================================================
var (
	// SSHD: Mengincar kata kunci spesifik dan menangkap IP setelah kata "from"
	RegexSSHD        = regexp.MustCompile(`(?i)(?:Failed password|Invalid user|maximum authentication attempts|Disconnecting authenticating user|preauth).*?from\s+(?:::ffff:)?([a-fA-F0-9\.:]+)`)
	
	// FTPD: Pure-FTPd dan ProFTPd (Mengabaikan log jika format rusak)
	RegexFTPD        = regexp.MustCompile(`(?i)(?:pure-ftpd:.*?\(\?@(?:::ffff:)?([a-fA-F0-9\.:]+)\).*?Authentication failed|proftpd\[.*?\].*?(?:::ffff:)?([a-fA-F0-9\.:]+)\s*(?:\[.*?\])?\s*:\s*Incorrect password)`)
	
	// EXIM / POSTFIX: Khusus Exim, kita memaksa Regex melompati IP Localhost di dalam kurung biasa "([ ... ])"
	// dan langsung menembak IP yang menempel DENGAN TITIK DUA "]:", karena itu adalah letak IP Publik Asli.
	RegexExim        = regexp.MustCompile(`(?i)(?:authenticator failed|auth failed|Authentication failed|SASL LOGIN).*?\[(?:IPv6:)?(?:::ffff:)?([a-fA-F0-9\.:]+)\]:`)
	
	// CONTROL PANELS
	RegexCpanel      = regexp.MustCompile(`(?i)FAILED LOGIN.*?(?:from)?\s*(?:::ffff:)?([a-fA-F0-9\.:]+)`)
	RegexDirectAdmin = regexp.MustCompile(`(?i)'(?:::ffff:)?([a-fA-F0-9\.:]+)'\s+failed login attempt`)
	RegexPlesk       = regexp.MustCompile(`(?i)(?:plesk|failed login attempt).*?from IP\s+(?:::ffff:)?([a-fA-F0-9\.:]+)`)
	RegexCyberPanel  = regexp.MustCompile(`(?i)(?:Login failed|Invalid login).*?(?:IP:|from)\s*(?:::ffff:)?([a-fA-F0-9\.:]+)`)
	RegexAAPanel     = regexp.MustCompile(`(?i)(?:fail|invalid|Failed login).*?(?:IP:|from)\s*(?:::ffff:)?([a-fA-F0-9\.:]+)`)
	
	// MODSECURITY WAF: Sering kali menyertakan port "1.2.3.4:54321", kita buat capture group yang non-greedy
	RegexModSec      = regexp.MustCompile(`(?i)ModSecurity: Access denied.*?\[client\s+(?:::ffff:)?([a-fA-F0-9\.:]+?)(?::\d+)?\]`)
)

// ==============================================================================
// 2. IP SANITIZATION LAYER (MEMASTIKAN FORMAT IP 100% VALID UNTUK KERNEL)
// ==============================================================================

// cleanExtractedIP membuang sisa-sisa string kotor (seperti port atau prefix OS)
// yang mungkin tidak sengaja terbawa oleh Regex, memastikan Firewall tidak error.
func cleanExtractedIP(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "::ffff:")
	raw = strings.TrimPrefix(raw, "IPv6:")
	
	// Jika formatnya adalah IPv4 yang ditempeli Port (contoh: 192.168.1.1:54321)
	// Kita pisahkan dan ambil IP-nya saja dengan aman.
	if strings.Contains(raw, ".") && strings.Contains(raw, ":") {
		host, _, err := net.SplitHostPort(raw)
		if err == nil {
			return host
		}
		// Fallback manual jika format string terlampau kotor
		parts := strings.Split(raw, ":")
		return parts[0]
	}
	return raw
}

// ==============================================================================
// 3. LOG PARSING ENGINE
// ==============================================================================

func parseLogLine(line, service string, maxLimit int) {
	// Fitur Panic Recovery: Memastikan daemon tidak pernah crash jika ada serangan regex anomali
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
		// Ambil IP dari Capture Group pertama yang valid/terisi
		for i := 1; i < len(match); i++ {
			if match[i] != "" { 
				rawIP = match[i]
				break 
			}
		}

		if rawIP != "" {
			// Bersihkan IP dari Port dan Prefix OS
			cleanIP := cleanExtractedIP(rawIP)
			
			// Validasi Absolut: Pastikan ini adalah IP yang sah
			if net.ParseIP(cleanIP) == nil {
				// [PERBAIKAN POINT 6] Laporan Regex Salah Tangkap (Mode Debug)
				utils.LogDebug("LFD TAILER: Ignored extracted string (Not a valid IP) -> '%s' from line: %s", cleanIP, line)
				return // Abaikan jika ternyata teks / string sampah
			}
			
			// [PERBAIKAN POINT 6] Info Debug Jika Berhasil Lolos Validasi
			utils.LogDebug("LFD TAILER: Confirmed Strike for %s. Evaluated regex group: '%s'", service, cleanIP)
			
			utils.LogWarn("STRIKE ALARM: IP %s failed %s authentication.", cleanIP, service)
			AddStrike(cleanIP, service, maxLimit)
		}
	} else {
		// Logika ini berguna untuk melihat secara mendalam baris log apa saja yang masuk ke tailer 
		// namun tidak cocok dengan regex (sangat verbose, karenanya hanya aktif saat RA_full_debug=1)
		utils.LogDebug("LFD TAILER: Line passed without strike -> %s", line)
	}
}

// tailFile membaca log menggunakan Inotify/Polling (Event-Driven, Low CPU)
func tailFile(filePath, service string, maxLimit int) {
	t, err := tail.TailFile(filePath, tail.Config{
		Follow:    true,
		ReOpen:    true,  // Penting: Melanjutkan jika log di-rotate oleh OS (logrotate)
		MustExist: false, // Penting: Menunggu file dibuat jika belum ada
		Poll:      true,  // Fallback aman untuk File System modern
		Location:  &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END},
	})
	
	if err != nil {
		utils.LogError("Failed to hook LFD to %s: %v", filePath, err)
		return
	}

	utils.LogInfo("LFD WATCHER: Active on %s [Target: %s | Limit: %d]", filePath, service, maxLimit)
	
	for line := range t.Lines {
		if line.Err != nil { continue }
		// Lempar ke Goroutine terpisah agar proses tailing tidak tersendat (Non-Blocking)
		go parseLogLine(line.Text, service, maxLimit)
	}
}

// ==============================================================================
// 4. MULTI-OS PATH RESOLVER (SINGLE FILE STRICT MODE)
// ==============================================================================

// findLogPath mencari eksistensi file log di berbagai direktori standar OS
// Hanya mereturn 1 path pertama yang valid untuk menghemat resource (Sistem Asli RAF)
func findLogPath(candidates []string) string {
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil { 
			return p 
		}
	}
	// Fallback jika tidak ada yang ditemukan, kembalikan array pertama.
	return candidates[0] 
}

// ==============================================================================
// 5. LFD ENGINE ORCHESTRATOR
// ==============================================================================

func StartLFDEngine() {
	config.CoreData.Mutex.RLock()
	lfdEnabled := config.CoreData.Config["RAF_LF_DAEMON"]
	
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

	// Jika dimatikan di config, hentikan
	if lfdEnabled != "1" { 
		utils.LogInfo("LFD Engine is globally disabled in configuration.")
		return 
	}

	// Menyalakan sistem penunjang LFD
	go InitTempBans()
	go TempBanManager()
	go CleanupStrikes()

	// Spawn Watchers
	for svc, limitStr := range limits {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit <= 0 { 
			continue // Skip jika limit bernilai 0
		}

		var logPath string
		switch svc {
		case "SSHD": 
			logPath = findLogPath([]string{"/var/log/secure", "/var/log/auth.log"})
		case "FTPD": 
			logPath = findLogPath([]string{"/var/log/messages", "/var/log/syslog", "/var/log/proftpd/proftpd.log", "/var/log/pure-ftpd/pure-ftpd.log"})
		case "EXIM": 
			logPath = findLogPath([]string{"/var/log/exim_mainlog", "/var/log/exim4/mainlog", "/var/log/exim/mainlog", "/var/log/maillog"})
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
		
		go tailFile(logPath, svc, limit)
	}
}
