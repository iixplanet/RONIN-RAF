// file: main.go
package main

import (
	"fmt"
	"os"
	// "os/exec"
	"os/signal"
	"syscall"
	"time"
	"raf/cli"
	"raf/config"
	"raf/firewall"
	"raf/intelligence"
	"raf/ipc"
	"raf/lfd"
	"raf/utils"
)

const ConfigPath = "/usr/local/ronin/config.ronin"
const LogFile = "/usr/local/ronin/logs/raf_engine.log"

var testingTimer *time.Timer

func BootSequence() {
	utils.LogInfo("Synchronizing Configuration Data...")
	config.LoadAll(ConfigPath, config.AllowFile, config.DenyFile)
	intelligence.InitAndParse()
	firewall.ApplyIptables()
	intelligence.StartBackgroundWorkers()
	utils.LogInfo("Network Defense Layer Active.")

	// SINKRONISASI: Fitur RAF_TESTING (Anti-Lockout)
	if config.CoreData.Config["RAF_TESTING"] == "1" {
		utils.LogWarn("TESTING MODE ACTIVE: Firewall will auto-flush in 5 minutes!")
		if testingTimer != nil { testingTimer.Stop() }
		testingTimer = time.AfterFunc(5*time.Minute, func() {
			utils.LogWarn("TESTING TIMER EXPIRED: Flushing all rules to prevent lockout...")
			firewall.Teardown()
		})
	} else {
		if testingTimer != nil { testingTimer.Stop() }
	}
}

func main() {
	if len(os.Args) > 1 {
		cli.Execute(os.Args[1:])
		return
	}

	fmt.Println("======================================================")
	fmt.Println(" RONIN AEGIS FIREWALL (RAF) - CORE ENGINE (PHASE 6)   ")
	fmt.Println("======================================================")

	utils.InitLogger(LogFile)
	utils.LogInfo("Daemon Booting Sequence Executed.")

	os.MkdirAll("/usr/local/ronin/lib/raf/", 0755)
	if _, err := os.Stat(config.AllowFile); os.IsNotExist(err) {
		os.WriteFile(config.AllowFile, []byte("# Whitelist\n127.0.0.1\n"), 0644)
	}
	if _, err := os.Stat(config.DenyFile); os.IsNotExist(err) {
		os.WriteFile(config.DenyFile, []byte("# Blacklist\n"), 0644)
	}

	BootSequence()
	lfd.StartLFDEngine()
	ipc.StartServer(BootSequence)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	utils.LogInfo("RAF Core is now running and waiting for events/signals.")

	for {
		sig := <-sigChan
		if sig == syscall.SIGHUP {
			utils.LogInfo("SIGHUP received: Executing Zero-Downtime Hot-Reload...")
			BootSequence() 
		} else {
			utils.LogInfo("Shutdown Signal received. Terminating safely...")
			firewall.Teardown()
			break
		}
	}
	utils.LogInfo("Daemon Offline.")
}
