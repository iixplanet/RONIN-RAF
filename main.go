// file: main.go (FINAL)
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"raf/cli"           // <== TAMBAHKAN
	"raf/config"
	"raf/firewall"
	"raf/intelligence"
	"raf/ipc"           // <== TAMBAHKAN
	"raf/lfd"
	"raf/utils"
)

const ConfigPath = "/usr/local/ronin/config.ronin"
const LogFile = "/usr/local/ronin/logs/raf_engine.log"

func BootSequence() {
	utils.LogInfo("Synchronizing Configuration Data...")
	// Panggil const AllowFile dan DenyFile yang kita set di config/parser.go
	config.LoadAll(ConfigPath, config.AllowFile, config.DenyFile)
	intelligence.InitAndParse()
	firewall.ApplyIptables()
	intelligence.StartBackgroundWorkers()
	utils.LogInfo("Network Defense Layer Active.")
}

func main() {
	// 1. CEK ARGUMEN TERMINAL
	// Jika dijalankan dengan argumen (misal: ./ronin-raf-daemon -d 1.1.1.1)
	if len(os.Args) > 1 {
		cli.Execute(os.Args[1:])
		return
	}

	// 2. JALANKAN SEBAGAI DAEMON UTAMA
	fmt.Println("======================================================")
	fmt.Println("             RONIN AEGIS FIREWALL (RAF)               ")
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

	// 3. START IPC COMMAND CENTER
	// Menerima perintah dari Terminal CLI
	ipc.StartServer(BootSequence)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	utils.LogInfo("RAF Core is now running and waiting for events/signals.")

	// file: main.go (Perbarui blok shutdown di dalam func main)

	for {
		sig := <-sigChan
		if sig == syscall.SIGHUP {
			utils.LogInfo("SIGHUP received: Executing Zero-Downtime Hot-Reload...")
			BootSequence() 
		} else {
			// ========================================================
			// BLOK SHUTDOWN YANG DIPERBARUI (TOTAL FLUSH)
			// ========================================================
			utils.LogInfo("Shutdown Signal received. Terminating safely...")
			
			// Panggil fungsi flush & destroy total seperti `csf -x`
			firewall.Teardown()
			
			break
		}
	}
	utils.LogInfo("Daemon Offline.")
}
