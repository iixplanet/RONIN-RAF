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

// Regex Definitions (Standard CSF Parity)
var (
	RegexSSHD        = regexp.MustCompile(`(?i)(?:Failed password for|Invalid user|Failed keyboard-interactive).*?from ([\d\.]+|[a-fA-F0-9:]+)`)
	RegexFTPD        = regexp.MustCompile(`(?i)pure-ftpd:.*?\(.*?@([\d\.]+|[a-fA-F0-9:]+)\) \[WARNING\] Authentication failed`)
	RegexExim        = regexp.MustCompile(`(?i)(?:authenticator failed|fixed_login).*? \[([\d\.]+|[a-fA-F0-9:]+)\](?::\d+)?.*?(: 535 Incorrect authentication data)`)
	RegexCpanel      = regexp.MustCompile(`(?i)FAILED LOGIN.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	RegexDirectAdmin = regexp.MustCompile(`(?i)Failed login attempt.*?ip=([\d\.]+|[a-fA-F0-9:]+)`)
	RegexModSec      = regexp.MustCompile(`(?i)ModSecurity: Access denied.*?\[client ([\d\.]+|[a-fA-F0-9:]+)\]`)
)

func parseLogLine(line, service string, maxLimit int) {
	var match []string
	switch service {
	case "SSHD":
		match = RegexSSHD.FindStringSubmatch(line)
	case "FTPD":
		match = RegexFTPD.FindStringSubmatch(line)
	case "EXIM":
		match = RegexExim.FindStringSubmatch(line)
	case "CPANEL":
		match = RegexCpanel.FindStringSubmatch(line)
	case "DIRECTADMIN":
		match = RegexDirectAdmin.FindStringSubmatch(line)
	case "MODSEC":
		match = RegexModSec.FindStringSubmatch(line)
	}

	if len(match) > 1 {
		ip := strings.TrimSpace(match[1])
		AddStrike(ip, service, maxLimit)
	}
}

func tailFile(filePath, service string, maxLimit int) {
	t, err := tail.TailFile(filePath, tail.Config{
		Follow:    true,
		ReOpen:    true,  // Menangani log rotation otomatis
		MustExist: false, // Jika file belum ada, tunggu sampai ada
		Location:  &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END}, // Baca dari ujung
	})

	if err != nil {
		utils.LogError("Failed to hook LFD to %s: %v", filePath, err)
		return
	}

	utils.LogInfo("LFD WATCHER: Hooked into %s [Target: %s | Limit: %d]", filePath, service, maxLimit)

	for line := range t.Lines {
		go parseLogLine(line.Text, service, maxLimit)
	}
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
		"MODSEC":      config.CoreData.Config["RAF_LF_MODSEC"],
	}
	config.CoreData.Mutex.RUnlock()

	if lfdEnabled != "1" {
		utils.LogInfo("LFD Engine is globally disabled in configuration.")
		return
	}

	// Nyalakan background workers
	go InitTempBans()
	go TempBanManager()
	go CleanupStrikes()

	// Assign limits & Tailing log paths
	for svc, limitStr := range limits {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			continue // Skip if limit is not set or 0
		}

		var logPath string
		switch svc {
		case "SSHD":
			if _, err := os.Stat("/var/log/secure"); err == nil {
				logPath = "/var/log/secure"
			} else {
				logPath = "/var/log/auth.log"
			}
		case "FTPD":
			if _, err := os.Stat("/var/log/messages"); err == nil {
				logPath = "/var/log/messages"
			} else {
				logPath = "/var/log/syslog"
			}
		case "EXIM":
			if _, err := os.Stat("/var/log/exim_mainlog"); err == nil {
				logPath = "/var/log/exim_mainlog"
			} else {
				logPath = "/var/log/exim4/mainlog"
			}
		case "CPANEL":
			logPath = "/usr/local/cpanel/logs/login_log"
		case "DIRECTADMIN":
			logPath = "/var/log/directadmin/login.log"
		case "MODSEC":
			logPath = "/var/log/modsec_audit.log"
		}

		// Jalankan watcher
		go tailFile(logPath, svc, limit)
	}
}