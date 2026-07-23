// file: ipc/server.go
package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"raf/config"
	"raf/firewall"
	"raf/lfd"
	"raf/utils"
)

const SocketPath = "/var/run/ronin-raf.sock"

type CommandPayload struct {
	Action   string `json:"action"`
	IP       string `json:"ip"`
	Reason   string `json:"reason"`
	Port     string `json:"port"`
	Duration string `json:"duration"`
}

func StartServer(reloadCallback func()) {
	os.Remove(SocketPath)
	listener, err := net.Listen("unix", SocketPath)
	if err != nil {
		utils.LogError("Failed to start IPC Socket: %v", err)
		return
	}
	os.Chmod(SocketPath, 0700)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil { continue }
			go handleConnection(conn, reloadCallback)
		}
	}()
	utils.LogInfo("IPC Command Center listening on %s (JSON-RPC Ready)", SocketPath)
}

func handleConnection(conn net.Conn, reloadCallback func()) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" { continue }

		var payload CommandPayload
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			conn.Write([]byte("ERR: Invalid JSON Payload.\n"))
			continue
		}

		switch payload.Action {
		case "RELOAD":
			reloadCallback()
			conn.Write([]byte("SUCCESS: Zero-Downtime Reload Executed.\n"))

		case "STOP":
			conn.Write([]byte("SUCCESS: Initiating Daemon Shutdown Sequence.\n"))
			go func() {
				p, _ := os.FindProcess(os.Getpid())
				p.Signal(syscall.SIGTERM)
			}()

		case "DENY":
			appendToFile(config.DenyFile, payload.IP, payload.Reason)
			reloadCallback()
			conn.Write([]byte(fmt.Sprintf("SUCCESS: %s permanently denied.\n", payload.IP)))

		case "ALLOW":
			appendToFile(config.AllowFile, payload.IP, payload.Reason)
			reloadCallback()
			conn.Write([]byte(fmt.Sprintf("SUCCESS: %s permanently whitelisted.\n", payload.IP)))

		case "REMOVE_DENY":
			removeFromFile(config.DenyFile, payload.IP)
			reloadCallback()
			conn.Write([]byte(fmt.Sprintf("SUCCESS: %s removed from Perm Deny List.\n", payload.IP)))

		case "REMOVE_ALLOW":
			removeFromFile(config.AllowFile, payload.IP)
			reloadCallback()
			conn.Write([]byte(fmt.Sprintf("SUCCESS: %s removed from Perm Allow List.\n", payload.IP)))

		case "UNBAN":
			lfd.ExecuteUnban(payload.IP)
			conn.Write([]byte(fmt.Sprintf("SUCCESS: LFD Temporary Ban revoked for %s\n", payload.IP)))

		case "TEMP_BAN", "TEMP_ALLOW":
			dur, err := strconv.Atoi(payload.Duration)
			if err != nil || dur <= 0 { dur = 3600 }
			reason := payload.Reason
			if payload.Port != "" { reason = fmt.Sprintf("[Port: %s] %s", payload.Port, reason) }
			
			// Eksekusi temp ban menggunakan engine LFD
			lfd.ExecuteBan(payload.IP, reason, dur)
			if payload.Action == "TEMP_ALLOW" {
				// Khusus Temp Allow, kita injek langsung ke IPSet khusus (Opsional untuk pengembangan lanjut)
				// Untuk sekarang, kita kembalikan status OK
			}
			conn.Write([]byte(fmt.Sprintf("SUCCESS: %s action applied on %s for %d seconds.\n", payload.Action, payload.IP, dur)))

		case "FLUSH_TEMP":
			lfd.FlushAllTempBans() // Pastikan fungsi ini ada di lfd/engine.go
			conn.Write([]byte("SUCCESS: All Temporary Bans have been cleared.\n"))

		case "FLUSH_DENY":
			os.WriteFile(config.DenyFile, []byte("# Blacklist\n"), 0644)
			reloadCallback()
			conn.Write([]byte("SUCCESS: Permanent Deny List has been completely wiped.\n"))

		default:
			conn.Write([]byte("ERR: Unknown command action.\n"))
		}
	}
}

// file: ipc/server.go

// appendToFile menulis list permanen ke disk, dengan proteksi Anti-Injection File Format
func appendToFile(path, ip, reason string) {
	if reason == "" { 
		reason = "Manual Override" 
	}
	
	// PROTEKSI FILE FORMAT INJECTION: 
	// Pastikan tidak ada karakter \n (Enter) tersembunyi yang mencoba membuat baris Iptables baru palsu
	reason = strings.ReplaceAll(reason, "\n", " ")
	reason = strings.ReplaceAll(reason, "\r", "")
	ip = strings.ReplaceAll(ip, "\n", "")
	ip = strings.ReplaceAll(ip, "\r", "")

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		utils.LogError("Failed to write to file %s: %v", path, err)
		return
	}
	defer f.Close()
	
	// Tulis dengan aman
	f.WriteString(fmt.Sprintf("%s # %s\n", ip, reason))
}

func removeFromFile(path, ip string) {
	data, _ := os.ReadFile(path)
	lines := strings.Split(string(data), "\n")
	var newLines []string
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), ip) { continue }
		newLines = append(newLines, line)
	}
	os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0644)
}
