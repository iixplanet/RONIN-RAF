// file: lfd/tailer.go
package lfd

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"raf/config"
	"raf/utils"
	"github.com/nxadm/tail"
)

var (
	// Anti False-Positive Regex (Strict Match)
	RegexSSHD        = regexp.MustCompile(`(?i)(?:Failed password for|Invalid user|Connection closed by authenticating user).*?(?:from|)\s*([\d\.]+|[a-fA-F0-9:]+)`)
	RegexFTPD        = regexp.MustCompile(`(?i)(?:pure-ftpd:.*?\(.*?@([\d\.]+|[a-fA-F0-9:]+)\) \[WARNING\] Authentication failed|proftpd\[.*?\].*?([\d\.]+|[a-fA-F0-9:]+) .*?: Incorrect password)`)
	RegexExim        = regexp.MustCompile(`(?i)(?:authenticator failed|auth failed).*?\[([\d\.]+|[a-fA-F0-9:]+)\]`)
	RegexCpanel      = regexp.MustCompile(`(?i)FAILED LOGIN.*?([\d\.]+|[a-fA-F0-9:]+)`)
	RegexDirectAdmin = regexp.MustCompile(`(?i)'([\d\.]+|[a-fA-F0-9:]+)'\s+failed login attempt`)
	RegexPlesk       = regexp.MustCompile(`(?i)Failed login attempt.*?from IP ([\d\.]+|[a-fA-F0-9:]+)`)
	RegexCyberPanel  = regexp.MustCompile(`(?i)CyberPanel.*?(?:fail|invalid).*?([\d\.]+|[a-fA-F0-9:]+)`)
	RegexAAPanel     = regexp.MustCompile(`(?i)aaPanel.*?(?:fail|invalid).*?([\d\.]+|[a-fA-F0-9:]+)`)
	RegexModSec      = regexp.MustCompile(`(?i)ModSecurity: Access denied.*?\[client ([\d\.]+|[a-fA-F0-9:]+)\]`)
)

func parseLogLine(line, service string, maxLimit int) {
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
		var ip string
		for i := 1; i < len(match); i++ {
			if match[i] != "" { ip = match[i]; break }
		}
		if ip != "" {
			ip = strings.TrimSpace(ip)
			utils.LogInfo("LFD STRIKE DETECTED: IP %s failed %s login.", ip, service)
			AddStrike(ip, service, maxLimit)
		}
	}
}

func tailFile(filePath, service string, maxLimit int) {
	t, err := tail.TailFile(filePath, tail.Config{
		Follow: true, ReOpen: true, MustExist: false,
		Location: &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END},
	})
	if err != nil { return }

	utils.LogInfo("LFD WATCHER: Hooked into %s [Target: %s | Limit: %d]", filePath, service, maxLimit)
	for line := range t.Lines {
		go parseLogLine(line.Text, service, maxLimit)
	}
}

// Log Path Multi-OS Fallback Scanner
func findLogPath(candidates []string) string {
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil { return p }
	}
	return candidates[0] // Fallback ke yang pertama meski blm ada
}

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

	if lfdEnabled != "1" { return }

	go InitTempBans()
	go TempBanManager()
	go CleanupStrikes()

	for svc, limitStr := range limits {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit <= 0 { continue }

		var logPath string
		switch svc {
		case "SSHD": logPath = findLogPath([]string{"/var/log/secure", "/var/log/auth.log"})
		case "FTPD": logPath = findLogPath([]string{"/var/log/messages", "/var/log/syslog", "/var/log/proftpd/proftpd.log"})
		case "EXIM": logPath = findLogPath([]string{"/var/log/exim_mainlog", "/var/log/exim4/mainlog", "/var/log/maillog"})
		case "CPANEL": logPath = "/usr/local/cpanel/logs/login_log"
		case "DIRECTADMIN": logPath = "/var/log/directadmin/login.log"
		case "PLESK": logPath = "/var/log/plesk/panel.log"
		case "CYBERPANEL": logPath = "/usr/local/lsws/logs/error.log"
		case "AAPANEL": logPath = "/www/server/panel/logs/error.log"
		case "MODSEC": logPath = "/var/log/modsec_audit.log"
		}
		go tailFile(logPath, svc, limit)
	}
}
