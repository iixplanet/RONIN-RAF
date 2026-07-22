// file: ipc/server.go
package ipc

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"raf/config"
	"raf/lfd"
	"raf/utils"
)

const SocketPath = "/var/run/ronin-raf.sock"

// StartServer memulai pendengar instruksi IPC (Inter-Process Communication)
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
	utils.LogInfo("IPC Command Center listening on %s", SocketPath)
}

func handleConnection(conn net.Conn, reloadCallback func()) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		cmd := strings.TrimSpace(scanner.Text())
		if cmd == "" { continue }
		
		parts := strings.SplitN(cmd, " ", 3)
		action := strings.ToUpper(parts[0])

		switch action {
		case "RELOAD":
			reloadCallback()
			conn.Write([]byte("OK: Zero-Downtime Reload Executed.\n"))

		case "STOP":
			conn.Write([]byte("OK: Initiating Daemon Shutdown Sequence.\n"))
			go func() {
				p, _ := os.FindProcess(os.Getpid())
				p.Signal(syscall.SIGTERM) // Kirim sinyal bunuh diri dengan elegan
			}()

		case "DENY":
			if len(parts) >= 2 {
				ip := parts[1]
				reason := "Manual CLI Block"
				if len(parts) > 2 { reason = parts[2] }
				appendToFile(config.DenyFile, ip, reason)
				reloadCallback()
				conn.Write([]byte(fmt.Sprintf("OK: %s permanently denied.\n", ip)))
			}

		case "ALLOW":
			if len(parts) >= 2 {
				ip := parts[1]
				reason := "Manual CLI Allow"
				if len(parts) > 2 { reason = parts[2] }
				appendToFile(config.AllowFile, ip, reason)
				reloadCallback()
				conn.Write([]byte(fmt.Sprintf("OK: %s permanently whitelisted.\n", ip)))
			}

		case "REMOVE_DENY":
			if len(parts) >= 2 {
				removeFromFile(config.DenyFile, parts[1])
				reloadCallback()
				conn.Write([]byte(fmt.Sprintf("OK: %s removed from Deny List.\n", parts[1])))
			}

		case "REMOVE_ALLOW":
			if len(parts) >= 2 {
				removeFromFile(config.AllowFile, parts[1])
				reloadCallback()
				conn.Write([]byte(fmt.Sprintf("OK: %s removed from Allow List.\n", parts[1])))
			}

		case "UNBAN": // LFD Temp Unban
			if len(parts) >= 2 {
				lfd.ExecuteUnban(parts[1])
				conn.Write([]byte(fmt.Sprintf("OK: LFD Temporary Ban removed for %s\n", parts[1])))
			}

		default:
			conn.Write([]byte("ERR: Unknown command code.\n"))
		}
	}
}

func appendToFile(path, ip, reason string) {
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	defer f.Close()
	f.WriteString(fmt.Sprintf("%s # %s\n", ip, reason))
}

func removeFromFile(path, ip string) {
	data, _ := os.ReadFile(path)
	lines := strings.Split(string(data), "\n")
	var newLines []string
	for _, line := range lines {
		clean := strings.TrimSpace(line)
		if strings.HasPrefix(clean, ip) {
			continue // Skip baris ini (Hapus IP)
		}
		newLines = append(newLines, line)
	}
	os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0644)
}