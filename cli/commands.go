// file: cli/commands.go
package cli

import (
	"fmt"
	"net"
	"os"
)

func Execute(args []string) {
	if len(args) == 0 {
		printHelp()
		return
	}

	cmd := args[0]
	switch cmd {
	case "-r", "--restart":
		sendCommand("RELOAD")
	case "-x", "--stop":
		sendCommand("STOP")
	case "-d", "--deny":
		if len(args) < 2 { fmt.Println("Usage: raf -d <ip> [comment]"); return }
		comment := "Manual CLI Block"
		if len(args) > 2 { comment = args[2] }
		sendCommand(fmt.Sprintf("DENY %s %s", args[1], comment))
	case "-dr", "--denyrm":
		if len(args) < 2 { fmt.Println("Usage: raf -dr <ip>"); return }
		sendCommand(fmt.Sprintf("REMOVE_DENY %s", args[1]))
	case "-a", "--allow":
		if len(args) < 2 { fmt.Println("Usage: raf -a <ip> [comment]"); return }
		comment := "Manual CLI Allow"
		if len(args) > 2 { comment = args[2] }
		sendCommand(fmt.Sprintf("ALLOW %s %s", args[1], comment))
	case "-ar", "--allowrm":
		if len(args) < 2 { fmt.Println("Usage: raf -ar <ip>"); return }
		sendCommand(fmt.Sprintf("REMOVE_ALLOW %s", args[1]))
	case "-tr", "--temprm":
		if len(args) < 2 { fmt.Println("Usage: raf -tr <ip>"); return }
		sendCommand(fmt.Sprintf("UNBAN %s", args[1]))
	case "-h", "--help":
		printHelp()
	default:
		fmt.Printf("Unknown option: %s\n", cmd)
		printHelp()
	}
}

func sendCommand(cmdStr string) {
	conn, err := net.Dial("unix", "/var/run/ronin-raf.sock")
	if err != nil {
		fmt.Println("Error: RAF Daemon is not running or Socket is inaccessible.")
		return
	}
	defer conn.Close()

	conn.Write([]byte(cmdStr + "\n"))
	
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	fmt.Print(string(buf[:n])) // Print balasan dari Daemon
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