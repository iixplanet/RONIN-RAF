// file: cli/commands.go
package cli

import (
	"encoding/json"
	"fmt"
	"net"
)

type CommandPayload struct {
	Action   string `json:"action"`
	IP       string `json:"ip"`
	Reason   string `json:"reason"`
	Port     string `json:"port"`
	Duration string `json:"duration"`
}

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
		if len(args) < 2 { fmt.Println("Usage: raf -d <ip> [comment]"); return }
		reason := "Manual CLI Block"
		if len(args) > 2 { reason = args[2] }
		sendCommand(CommandPayload{Action: "DENY", IP: args[1], Reason: reason})
	case "-dr", "--denyrm":
		if len(args) < 2 { fmt.Println("Usage: raf -dr <ip>"); return }
		sendCommand(CommandPayload{Action: "REMOVE_DENY", IP: args[1]})
	case "-a", "--allow":
		if len(args) < 2 { fmt.Println("Usage: raf -a <ip> [comment]"); return }
		reason := "Manual CLI Allow"
		if len(args) > 2 { reason = args[2] }
		sendCommand(CommandPayload{Action: "ALLOW", IP: args[1], Reason: reason})
	case "-ar", "--allowrm":
		if len(args) < 2 { fmt.Println("Usage: raf -ar <ip>"); return }
		sendCommand(CommandPayload{Action: "REMOVE_ALLOW", IP: args[1]})
	case "-tr", "--temprm":
		if len(args) < 2 { fmt.Println("Usage: raf -tr <ip>"); return }
		sendCommand(CommandPayload{Action: "UNBAN", IP: args[1]})
	case "-h", "--help":
		printHelp()
	default:
		fmt.Printf("Unknown option: %s\n", cmd)
		printHelp()
	}
}

func sendCommand(payload CommandPayload) {
	conn, err := net.Dial("unix", "/var/run/ronin-raf.sock")
	if err != nil {
		fmt.Println("Error: RAF Daemon is not running or Socket is inaccessible.")
		return
	}
	defer conn.Close()

	data, _ := json.Marshal(payload)
	conn.Write(append(data, '\n'))
	
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	fmt.Print(string(buf[:n]))
}

func printHelp() {
	fmt.Println(`RONIN AEGIS FIREWALL (RAF) CLI COMMANDS
Usage: raf [options]

Options:
  -r,  --restart          Hot-Reload Firewall rules (Zero-Downtime)
  -x,  --stop             Stop Daemon & Flush all Iptables Rules
  -d,  --deny <ip>        Block an IP address permanently
  -dr, --denyrm <ip>      Remove an IP from permanent block
  -a,  --allow <ip>       Whitelist an IP address permanently
  -ar, --allowrm <ip>     Remove an IP from whitelist
  -tr, --temprm <ip>      Remove an IP from temporary block (LFD)
  -h,  --help             Show this help menu
`)
}
