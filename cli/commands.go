// file: cli/commands.go
package cli

import (
	"encoding/json"
	"fmt"
	"net"
	// "os"
	"strings"
	"time"
)

// CommandPayload adalah struktur JSON untuk komunikasi dengan Daemon via Unix Socket
type CommandPayload struct {
	Action   string `json:"action"`
	IP       string `json:"ip"`
	Reason   string `json:"reason"`
	Port     string `json:"port"`
	Duration string `json:"duration"`
}

// Execute mem-parsing argumen terminal dan menembakkannya ke Socket
func Execute(args []string) {
	if len(args) == 0 {
		printHelp()
		return
	}

	cmd := args[0]
	switch cmd {
	case "-r", "--restart":
		sendCommand(CommandPayload{Action: "RELOAD"})
		
	case "-x", "--stop":
		sendCommand(CommandPayload{Action: "STOP"})

	case "-d", "--deny":
		if len(args) < 2 {
			colorPrint("red", "Usage: raf -d <ip> [comment]")
			return
		}
		reason := "Manual CLI Block"
		if len(args) > 2 { reason = strings.Join(args[2:], " ") }
		sendCommand(CommandPayload{Action: "DENY", IP: args[1], Reason: reason})

	case "-dr", "--denyrm":
		if len(args) < 2 {
			colorPrint("red", "Usage: raf -dr <ip>")
			return
		}
		sendCommand(CommandPayload{Action: "REMOVE_DENY", IP: args[1]})

	case "-a", "--allow":
		if len(args) < 2 {
			colorPrint("red", "Usage: raf -a <ip> [comment]")
			return
		}
		reason := "Manual CLI Allow"
		if len(args) > 2 { reason = strings.Join(args[2:], " ") }
		sendCommand(CommandPayload{Action: "ALLOW", IP: args[1], Reason: reason})

	case "-ar", "--allowrm":
		if len(args) < 2 {
			colorPrint("red", "Usage: raf -ar <ip>")
			return
		}
		sendCommand(CommandPayload{Action: "REMOVE_ALLOW", IP: args[1]})

	case "-td", "--tempdeny":
		// Format: raf -td <ip> <seconds> [port] [comment]
		if len(args) < 3 {
			colorPrint("red", "Usage: raf -td <ip> <duration_seconds> [port] [comment]")
			return
		}
		port := ""
		reason := "Manual CLI Temp Ban"
		if len(args) > 3 { port = args[3] }
		if len(args) > 4 { reason = strings.Join(args[4:], " ") }
		// Normalisasi jika user mengosongkan port tapi mengisi komentar (menggunakan bintang/minus)
		if port == "*" || port == "-" { port = "" }
		
		sendCommand(CommandPayload{Action: "TEMP_BAN", IP: args[1], Duration: args[2], Port: port, Reason: reason})

	case "-ta", "--tempallow":
		// Format: raf -ta <ip> <seconds> [port] [comment]
		if len(args) < 3 {
			colorPrint("red", "Usage: raf -ta <ip> <duration_seconds> [port] [comment]")
			return
		}
		port := ""
		reason := "Manual CLI Temp Allow"
		if len(args) > 3 { port = args[3] }
		if len(args) > 4 { reason = strings.Join(args[4:], " ") }
		if port == "*" || port == "-" { port = "" }
		
		sendCommand(CommandPayload{Action: "TEMP_ALLOW", IP: args[1], Duration: args[2], Port: port, Reason: reason})

	case "-tr", "--temprm":
		if len(args) < 2 {
			colorPrint("red", "Usage: raf -tr <ip>")
			return
		}
		sendCommand(CommandPayload{Action: "UNBAN", IP: args[1]})

	case "-tf", "--flush-temp":
		sendCommand(CommandPayload{Action: "FLUSH_TEMP"})

	case "-df", "--flush-deny":
		sendCommand(CommandPayload{Action: "FLUSH_DENY"})

	case "-h", "--help":
		printHelp()

	default:
		colorPrint("red", fmt.Sprintf("Unknown option: %s", cmd))
		printHelp()
	}
}

// sendCommand membuka koneksi ke Unix Socket Daemon dan mentransmisikan JSON
func sendCommand(payload CommandPayload) {
	conn, err := net.DialTimeout("unix", "/var/run/ronin-raf.sock", 3*time.Second)
	if err != nil {
		colorPrint("red", "ERROR: RAF Daemon is offline, dead, or socket is inaccessible.")
		colorPrint("yellow", "Try starting the daemon first using systemctl or executing it directly.")
		return
	}
	defer conn.Close()

	// Set Deadline agar terminal tidak hang jika Daemon nyangkut
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Marshal payload ke JSON dan kirim
	data, _ := json.Marshal(payload)
	_, err = conn.Write(append(data, '\n'))
	if err != nil {
		colorPrint("red", "ERROR: Broken pipe while sending command to Daemon.")
		return
	}
	
	// Baca balasan dari Daemon (Max 2KB)
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		colorPrint("red", "ERROR: Timeout waiting for Daemon response.")
		return
	}

	response := strings.TrimSpace(string(buf[:n]))
	
	// Warnai output berdasarkan status keberhasilan
	if strings.HasPrefix(response, "SUCCESS") {
		colorPrint("green", response)
	} else if strings.HasPrefix(response, "ERR") {
		colorPrint("red", response)
	} else {
		fmt.Println(response)
	}
}

// colorPrint mencetak teks ke terminal SSH dengan format warna ANSI
func colorPrint(color, text string) {
	switch color {
	case "green":
		fmt.Printf("\033[1;32m%s\033[0m\n", text)
	case "red":
		fmt.Printf("\033[1;31m%s\033[0m\n", text)
	case "yellow":
		fmt.Printf("\033[1;33m%s\033[0m\n", text)
	default:
		fmt.Println(text)
	}
}

// printHelp menampilkan panduan command line ala Unix Man Page
func printHelp() {
	fmt.Println(`
======================================================
 RONIN AEGIS FIREWALL (RAF) - COMMAND LINE INTERFACE
======================================================
Usage: raf [options] <ip> <parameters>

Basic Operations:
  -d,  --deny <ip> [comment]      : Permanently block an IP address
  -a,  --allow <ip> [comment]     : Permanently whitelist an IP
  -dr, --denyrm <ip>              : Remove an IP from permanent block
  -ar, --allowrm <ip>             : Remove an IP from whitelist

Advanced / Temporary Operations:
  -td, --tempdeny <ip> <sec> [port] [comment] : Block IP temporarily (e.g., raf -td 1.1.1.1 3600 22)
  -ta, --tempallow <ip> <sec> [port] [comment]: Allow IP temporarily
  -tr, --temprm <ip>                          : Remove an IP from temporary block (LFD)

System Overrides:
  -r,  --restart                  : Hot-Reload Firewall rules (Zero-Downtime)
  -x,  --stop                     : Stop Daemon & Flush all Iptables Rules
  -tf, --flush-temp               : Clear all Temporary Bans immediately
  -df, --flush-deny               : Clear all Permanent Deny rules

Examples:
  raf -d 192.168.1.10 "Hacker Attack"
  raf -td 10.0.0.1 86400 80 "HTTP Flood Mitigation"
  raf -tr 10.0.0.1
======================================================`)
}
