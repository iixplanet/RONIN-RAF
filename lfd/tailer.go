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
// 1. ENTERPRISE THREAT SIGNATURES (MULTI-REGEX DICTIONARY)
// ==============================================================================
// Sistem kini mengevaluasi log menggunakan array pola, memastikan akurasi 100% 
// lintas Sistem Operasi (CentOS, Ubuntu, dll) dan berbagai Control Panel.

var ThreatSignatures = map[string][]*regexp.Regexp{
	"SSHD": {
		// Standard Failed Password
		regexp.MustCompile(`(?i)Failed password for .*? from\s+(?:::ffff:)?([a-fA-F0-9\.:]+)`),
		// Invalid User attempt
		regexp.MustCompile(`(?i)Invalid user .*? from\s+(?:::ffff:)?([a-fA-F0-9\.:]+)`),
		// Connection closed during preauth (Common botnet scanning behavior)
		regexp.MustCompile(`(?i)Connection closed by (?:authenticating user|invalid user) .*?\s+(?:::ffff:)?([a-fA-F0-9\.:]+)\s+\[preauth\]`),
		// Max auth attempts exceeded
		regexp.MustCompile(`(?i)maximum authentication attempts exceeded for .*? from\s+(?:::ffff:)?([a-fA-F0-9\.:]+)`),
		// Disconnecting due to too many errors
		regexp.MustCompile(`(?i)Disconnecting (?:authenticating user|invalid user) .*?\s+(?:::ffff:)?([a-fA-F0-9\.:]+)`),
		// Bad Protocol / Nmap SSH script scan
		regexp.MustCompile(`(?i)Bad protocol version identification.*?from\s+(?:::ffff:)?([a-fA-F0-9\.:]+)`),
	},
	"FTPD": {
		// Pure-FTPd
		regexp.MustCompile(`(?i)pure-ftpd:.*?\(\?@(?:::ffff:)?([a-fA-F0-9\.:]+)\).*?Authentication failed`),
		// ProFTPd - Incorrect Password
		regexp.MustCompile(`(?i)proftpd\[.*?\].*?(?:::ffff:)?([a-fA-F0-9\.:]+)\s*(?:\[.*?\])?\s*:\s*USER.*?Incorrect password`),
		// ProFTPd - No such user
		regexp.MustCompile(`(?i)proftpd\[.*?\].*?(?:::ffff:)?([a-fA-F0-9\.:]+)\s*(?:\[.*?\])?\s*:\s*USER.*?No such user found`),
		// Vsftpd
		regexp.MustCompile(`(?i)vsftpd:.*?(?:::ffff:)?([a-fA-F0-9\.:]+)\s+FAIL LOGIN`),
	},
	"EXIM": {
		// Exim Mainlog Authenticator Failed
		regexp.MustCompile(`(?i)exim\[.*?\].*?(?:authenticator failed|auth failed|Authentication failed).*?\[(?:IPv6:)?(?:::ffff:)?([a-fA-F0-9\.:]+)\]:`),
		// Postfix SASL Login Failed
		regexp.MustCompile(`(?i)postfix/smtpd\[.*?\].*?warning:.*?(?:unknown|\[)(?:::ffff:)?([a-fA-F0-9\.:]+)(?:\])?: SASL [a-zA-Z]+ authentication failed`),
		// Dovecot Auth Failure
		regexp.MustCompile(`(?i)dovecot: (?:auth|pop3-login|imap-login):.*?Authentication failure.*?(?:rip|IP)=(?:::ffff:)?([a-fA-F0-9\.:]+)`),
		// Dovecot Aborted Login
		regexp.MustCompile(`(?i)dovecot:.*?(?:Aborted login|Disconnected).*?(?:auth failed).*?(?:rip|IP)=(?:::ffff:)?([a-fA-F0-9\.:]+)`),
	},
	"CPANEL": {
		// WHM / cPanel Main Login
		regexp.MustCompile(`(?i)FAILED LOGIN.*?(?:from)?\s*(?:::ffff:)?([a-fA-F0-9\.:]+)`),
		// Webmail Login
		regexp.MustCompile(`(?i)webmaild\[.*?\].*?FAILED LOGIN.*?(?:from)?\s*(?:::ffff:)?([a-fA-F0-9\.:]+)`),
		// CPHulkd / cPanel Bruteforce Protection Log
		regexp.MustCompile(`(?i)cphulkd\[.*?\].*?Login Permitted.*?from\s+(?:::ffff:)?([a-fA-F0-9\.:]+)`), // (Adjust if checking failed logs specifically)
	},
	"DIRECTADMIN": {
		// DA Standard format
		regexp.MustCompile(`(?i)'(?:::ffff:)?([a-fA-F0-9\.:]+)'\s+failed login attempt`),
		// DA failed to login
		regexp.MustCompile(`(?i)(?:::ffff:)?([a-fA-F0-9\.:]+)\s+failed to login`),
		// DA Blocking log
		regexp.MustCompile(`(?i)Blocking\s+(?:::ffff:)?([a-fA-F0-9\.:]+)\s+for\s+failed\s+login`),
	},
	"PLESK": {
		// Plesk Panel Main
		regexp.MustCompile(`(?i)(?:plesk|failed login attempt|Login failed).*?from IP\s+(?:::ffff:)?([a-fA-F0-9\.:]+)`),
		// SW-CP-SERVER (Nginx front-end for Plesk)
		regexp.MustCompile(`(?i)sw-cp-server.*?(?:Failed|Invalid) login.*?(?:::ffff:)?([a-fA-F0-9\.:]+)`),
	},
	"CYBERPANEL": {
		// CyberPanel general auth failures
		regexp.MustCompile(`(?i)(?:Login failed|Invalid login|Incorrect).*?(?:IP:|from)\s*(?:::ffff:)?([a-fA-F0-9\.:]+)`),
	},
	"AAPANEL": {
		// aaPanel general auth failures
		regexp.MustCompile(`(?i)(?:fail|invalid|Failed login|Login error).*?(?:IP:|from)\s*(?:::ffff:)?([a-fA-F0-9\.:]+)`),
	},
	"MODSEC": {
		// Apache / Nginx / LiteSpeed Classic Error Log Format (Menangkap IP yang berada DI DEPAN kata ModSecurity)
		regexp.MustCompile(`(?i)\[(?:client\s+)?(?:::ffff:)?([a-fA-F0-9\.:]+?)(?::\d+)?\].*?ModSecurity(?:\]|:).*?(?:Access denied|Warning|Access blocked)`),
		
		// Format Custom / Fallback (Menangkap IP yang berada DI BELAKANG kata ModSecurity)
		regexp.MustCompile(`(?i)ModSecurity(?:\]|:).*?(?:Access denied|Warning|Access blocked).*?\[(?:client\s+)?(?:::ffff:)?([a-fA-F0-9\.:]+?)(?::\d+)?\]`),
		
		// Nginx / libmodsecurity3 JSON Audit Log Format
		regexp.MustCompile(`(?i)"client_ip"\s*:\s*"([a-fA-F0-9\.:]+)"`),

		// ModSecurity Audit Log Format (Menangkap IP dari blok -A- dan mencocokkan blok -H-)
		regexp.MustCompile(`(?s)-+[a-zA-Z0-9]+-+A-+\s*\[[^\]]+\]\s+\S+\s+([a-fA-F0-9\.:]+).*?-+[a-zA-Z0-9]+-+H-+.*?(?:ModSecurity|Message).*?Access denied`),

		regexp.MustCompile(`(?i)ModSecurity(?:\]|:).*?Access denied with code 403.*?\[msg\s+"?\s*((?:[0-9]{1,3}\.){3}[0-9]{1,3})`),
		regexp.MustCompile(`(?s)A--\s*\[[^\]]+\]\s+\S+\s+([a-fA-F0-9\.:]+).*?-H--\s*(?:Message|ModSecurity).*?Access denied`),

		// Menangkap IP dari log Apache/LiteSpeed/Nginx untuk status "ModSecurity: Access denied with" (Connection Closed/Dropped)
		regexp.MustCompile(`(?i)\[(?:client|remote)\s+(?:::ffff:)?([a-fA-F0-9\.:]+)(?::\d+)?\].*?ModSecurity:\s*Access denied with`),
		
		// 4. LITESPEED NATIVE ERROR LOG STRICT MODE
		// Contoh log: [140.83.85.172:59721] [ModSecurity] Access denied with code 403
		regexp.MustCompile(`(?i)\[((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::\d+)?\].*?ModSecurity.*?Access denied with code 403`),

		// 5. cpanel apache v2 native
		regexp.MustCompile(`(?i)(?:ModSecurity: Access denied.*?\[client |^\[\d{1,2}/[a-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}[^\]]*\]\s+\S+\s+)([\d\.]+|[a-fA-F0-9:]+)`), // <--- HAPUS RegexModSec = dan TAMBAH KOMA (,) DI SINI
	},
}
	
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



func parseLogLine(line, service string, maxLimit int) {
	defer func() {
		if r := recover(); r != nil {
			utils.LogError("Recovered from panic in LFD Regex parser: %v", r)
		}
	}()

	// ====================================================================
	// [SMART FILTER MODSECURITY]
	// Hentikan proses jika status BUKAN 403 (Menyelamatkan Status 200 / Normal)
	// ====================================================================
	if service == "MODSEC" {
		is403 := strings.Contains(line, "\"http_code\":403") || 
				 strings.Contains(line, "\"http_code\": 403") ||
				 strings.Contains(line, "code 403") ||
				 strings.Contains(line, " 403 Forbidden") ||
		         strings.Contains(line, "Access denied")
		
		// Jika log ini bukan log pemblokiran (403), lewati (jangan blokir IP-nya)
		if !is403 {
			return 
		}
	}
	// ====================================================================

	signatures, exists := ThreatSignatures[service]
	if !exists { return } // Service tidak dikenali

	for _, regex := range signatures {
		match := regex.FindStringSubmatch(line)
		if len(match) > 1 {
			var rawIP string
			for i := 1; i < len(match); i++ {
				if match[i] != "" { 
					rawIP = match[i]
					break 
				}
			}

			if rawIP != "" {
				cleanIP := cleanExtractedIP(rawIP)
				if net.ParseIP(cleanIP) == nil {
					continue 
				}
				
				
				AddStrike(cleanIP, service, maxLimit)
				break
			} // Tutup if rawIP != ""
		} // Tutup if len(match) > 1
	} // Tutup for _, regex := range signatures
} // <--- INI ADALAH KURUNG KURAWAL YANG HILANG SEBELUMNYA
			
			
// tailFile membaca log menggunakan Inotify/Polling (Event-Driven, Low CPU)
func tailFile(filePath, service string, maxLimit int) {
	t, err := tail.TailFile(filePath, tail.Config{
		Follow:    true,
		ReOpen:    true,  // Penting: Melanjutkan jika log di-rotate oleh OS (logrotate)
		MustExist: false, // Penting: Menunggu file dibuat jika belum ada / salah ketik
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
// 5. LFD ENGINE ORCHESTRATOR & CUSTOM OVERRIDE
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

	// Tarik variabel Custom Log Path dari Dashboard
	customPaths := map[string]string{
		"SSHD":        config.CoreData.Config["RAF_LOG_SSHD"],
		"FTPD":        config.CoreData.Config["RAF_LOG_FTPD"],
		"EXIM":        config.CoreData.Config["RAF_LOG_EXIM"],
		"CPANEL":      config.CoreData.Config["RAF_LOG_CPANEL"],
		"DIRECTADMIN": config.CoreData.Config["RAF_LOG_DIRECTADMIN"],
		"PLESK":       config.CoreData.Config["RAF_LOG_PLESK"],
		"CYBERPANEL":  config.CoreData.Config["RAF_LOG_CYBERPANEL"],
		"AAPANEL":     config.CoreData.Config["RAF_LOG_AAPANEL"],
		"MODSEC":      config.CoreData.Config["RAF_LOG_MODSEC"],
	}
	config.CoreData.Mutex.RUnlock()

	// Jika dimatikan di config, hentikan
	if lfdEnabled != "1" { 
		utils.LogInfo("LFD Engine is globally disabled in configuration.")
		return 
	}

	go InitTempBans()
	go InitTempAllows()      // [TAMBAHAN BARU]
	go TempBanManager()
	go TempAllowManager()    // [TAMBAHAN BARU]
	go CleanupStrikes()

	// Spawn Watchers untuk tiap Layanan
	for svc, limitStr := range limits {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit <= 0 { 
			continue // Skip jika limit bernilai 0 (Fitur dimatikan)
		}

		// 1. Cek Prioritas Pertama: Manual Override dari Admin Dashboard
		logPath := strings.TrimSpace(customPaths[svc])
		
		// 2. Cek Prioritas Kedua: Jika kosong, gunakan Intelligent Auto-Discovery
		if logPath == "" {
			switch svc {
			case "SSHD": 
				logPath = findLogPath([]string{"/var/log/secure", "/var/log/auth.log"})
			case "FTPD": 
				logPath = findLogPath([]string{"/var/log/messages", "/var/log/syslog", "/var/log/proftpd/proftpd.log", "/var/log/pure-ftpd/pure-ftpd.log", "/var/log/vsftpd.log"})
			case "EXIM": 
				logPath = findLogPath([]string{"/var/log/exim_mainlog", "/var/log/exim4/mainlog", "/var/log/exim/mainlog", "/var/log/maillog", "/var/log/mail.log"})
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
				logPath = findLogPath([]string{"/var/log/modsec_audit.log", "/var/log/apache2/modsec_audit.log", "/dev/shm/modsec_audit.log", "/var/log/httpd/modsec_audit.log", "/var/log/modsec_audit.json"})
			}
		} else {
			// Informasikan jika Admin menggunakan Custom Override
			utils.LogInfo("LFD CONFIG: Service [%s] is using a Custom Log Path Override.", svc)
		}
		
		if logPath != "" {
			go tailFile(logPath, svc, limit)
		}
	}
}
