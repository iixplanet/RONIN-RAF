// file: main.go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"raf/config"
	"raf/firewall"
	"raf/lfd"
	"raf/utils"
)

const (
	ConfigPath = "/usr/local/ronin/config.ronin"
	AllowFile  = "/usr/local/ronin/lib/raf/raf.allow"
	DenyFile   = "/usr/local/ronin/lib/raf/raf.deny"
	LogFile    = "/usr/local/ronin/logs/raf_engine.log"
)

func BootSequence() {
	utils.LogInfo("Synchronizing Configuration Data...")
	config.LoadAll(ConfigPath, AllowFile, DenyFile)
	firewall.ApplyIptables()
	utils.LogInfo("Network Defense Layer Active.")
}

func main() {
	fmt.Println("======================================================")
	fmt.Println(" RONIN AEGIS FIREWALL (RAF) - CORE ENGINE (PHASE 1)   ")
	fmt.Println("======================================================")

	// 1. Initialize Logger
	utils.InitLogger(LogFile)
	utils.LogInfo("Daemon Booting Sequence Executed.")

	// 2. Buat file default jika belum ada
	os.MkdirAll("/usr/local/ronin/lib/raf/", 0755)
	if _, err := os.Stat(AllowFile); os.IsNotExist(err) {
		os.WriteFile(AllowFile, []byte("# Whitelist\n127.0.0.1\n"), 0644)
	}
	if _, err := os.Stat(DenyFile); os.IsNotExist(err) {
		os.WriteFile(DenyFile, []byte("# Blacklist\n"), 0644)
	}

	// 3. Build & Apply Firewall Rules
	BootSequence()
    lfd.StartLFDEngine()
	// 4. Setup Signal Trapper for Hot-Reload & Graceful Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	utils.LogInfo("RAF Core is now running and waiting for events/signals.")

	// Main Blocking Loop
	for {
		sig := <-sigChan
		if sig == syscall.SIGHUP {
			utils.LogInfo("SIGHUP received: Executing Zero-Downtime Hot-Reload...")
			BootSequence() // Reload config & re-inject iptables without dropping connections
		} else {
			utils.LogInfo("Shutdown Signal received. Terminating safely...")
			
			// Optional: Anda bisa memanggil iptables -D untuk membersihkan hook di sini
			exec.Command("iptables", "-D", "INPUT", "-j", "RAF_INPUT").Run()
			exec.Command("iptables", "-D", "OUTPUT", "-j", "RAF_OUTPUT").Run()
			
			break
		}
	}
	utils.LogInfo("Daemon Offline.")
}
