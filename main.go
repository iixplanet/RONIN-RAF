// file: main.go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
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

const (
	ConfigPath = "/usr/local/ronin/config.ronin"
	LogFile    = "/usr/local/ronin/logs/raf_engine.log"
	PidFile    = "/var/run/ronin-raf.pid"
)

var testingTimer *time.Timer

// ==============================================================================
// 1. BOOT ORCHESTRATOR
// ==============================================================================

// BootSequence merangkai proses inisialisasi Konfigurasi, Intelijen, dan Firewall
// Fungsi ini dipanggil saat Start pertama kali, dan setiap kali SIGHUP (Hot-Reload) diterima.
func BootSequence() {
	utils.LogInfo("RAF Synchronizing Configuration Data...")
	
	// 1. Load RAM Configuration
	config.LoadAll(ConfigPath, config.AllowFile, config.DenyFile)
	
	// 2. Load Threat Intelligence (GeoIP & Blocklists)
	intelligence.InitAndParse()
	
	// 3. Inject Rules to OS Kernel
	firewall.ApplyIptables()
	
	// =========================================================
	// 4. [PERBAIKAN BUG] Sinkronkan kembali memori Temp Ban/Allow 
	// yang hilang akibat proses Flush Kernel di poin (3) atas.
	// =========================================================
	lfd.SyncRoutinesToKernel()
	
	// 5. Start Background Downloader (Spamhaus, DShield, dll)
	intelligence.StartBackgroundWorkers()
	
	utils.LogInfo("RAF Network Defense Layer Active.")

	// ==========================================================
	// ANTI-LOCKOUT: TESTING MODE (AUTO-FLUSH TIMER)
	// ==========================================================
	config.CoreData.Mutex.RLock()
	isTesting := config.CoreData.Config["RAF_TESTING"] == "1"
	config.CoreData.Mutex.RUnlock()

	if isTesting {
		utils.LogWarn("TESTING MODE ACTIVE: Firewall will automatically flush in 5 minutes!")
		
		// Stop timer lama jika ini adalah proses Reload
		if testingTimer != nil { 
			testingTimer.Stop() 
		}
		
		// Set timer mundur 5 menit untuk mengeksekusi Teardown
		testingTimer = time.AfterFunc(5*time.Minute, func() {
			utils.LogWarn("TESTING TIMER EXPIRED: Flushing all rules to prevent permanent lockout...")
			firewall.Teardown()
		})
	} else {
		// Matikan timer jika user men-disable Testing Mode lalu me-reload
		if testingTimer != nil { 
			testingTimer.Stop() 
		}
	}
}

// ==============================================================================
// 2. DAEMON LIFECYCLE MANAGEMENT
// ==============================================================================

func writePID() {
	pid := os.Getpid()
	if err := os.WriteFile(PidFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
		utils.LogWarn("Could not write PID file to %s: %v", PidFile, err)
	}
}

func removePID() {
	os.Remove(PidFile)
}

// ==============================================================================
// 3. MAIN ENTRY POINT
// ==============================================================================

func main() {
	// A. CEK ARGUMEN COMMAND LINE (CLI)
	// Jika dijalankan dengan argumen (Contoh: `raf -d 1.1.1.1`), 
	// serahkan ke module CLI untuk mengirim payload ke Socket, lalu keluar (Exit).
	if len(os.Args) > 1 {
		cli.Execute(os.Args[1:])
		return
	}

	// [PERBAIKAN POINT 4] B0. ISOLASI PROSES DAEMON
	// Mencegah user mengeksekusi Daemon start secara langsung dari CLI yang 
	// berpotensi mematikan Daemon dashboard (Process Crash).
	if os.Getenv("CALLER") != "ronin-ui-dashboard" {
		fmt.Println("======================================================")
		fmt.Println("                RONIN AEGIS FIREWALL                  ")
		fmt.Println("======================================================")
		fmt.Println(" Example usage: raf -d 1.2.3 4")
		fmt.Println(" Type 'raf -h' for help.")
		os.Exit(1)
	}

	// B. PRE-FLIGHT CHECKS
	if os.Geteuid() != 0 {
		fmt.Println("CRITICAL ERROR: Ronin Aegis Firewall (RAF) Daemon must be run as ROOT!")
		os.Exit(1)
	}

	// C. BERSIHKAN LOG SAAT STARTUP
	// Menghindari file log membengkak jika daemon sering dimatikan/dinyalakan
	utils.ClearLog(LogFile)

	// D. TAMPILAN BANNER ENTERPRISE
	fmt.Println("======================================================")
	fmt.Println("             RONIN AEGIS FIREWALL (RAF)               ")
	fmt.Println("          Stateful Packet Inspection & LFD            ")
	fmt.Println("======================================================")

	// E. INIT LOGGER & PID
	utils.InitLogger(LogFile)
	utils.LogInfo("RAF Daemon Booting Sequence Initiated...")
	writePID()
	
	// F. GLOBAL PANIC RECOVERY
	// Memastikan jika ada bug fatal, daemon tidak mati diam-diam
	defer func() {
		if r := recover(); r != nil {
			utils.LogError("FATAL CRASH RECOVERED: %v", r)
			removePID()
		}
	}()

	// G. PASTIKAN DOKUMEN DASAR TERSEDIA
	os.MkdirAll("/usr/local/ronin/lib/raf/", 0755)
	if _, err := os.Stat(config.AllowFile); os.IsNotExist(err) {
		os.WriteFile(config.AllowFile, []byte("# Permanent Whitelist\n127.0.0.1\n"), 0644)
	}
	if _, err := os.Stat(config.DenyFile); os.IsNotExist(err) {
		os.WriteFile(config.DenyFile, []byte("# Permanent Blacklist\n"), 0644)
	}

	// H. EKSEKUSI BOOT KERNEL & SISTEM LFD
	BootSequence()
	lfd.StartLFDEngine()

	// I. NYALAKAN IPC COMMAND CENTER (Socket Pendengar dari Web UI & CLI)
	ipc.StartServer(BootSequence)

	// J. SIGNAL TRAPPER (MENUNGGU PERINTAH SYSTEMD/OS)
	sigChan := make(chan os.Signal, 1)
	// SIGINT (Ctrl+C), SIGTERM (Systemctl Stop), SIGHUP (Reload Config)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	utils.LogInfo("RAF Core is now running securely and waiting for events.")

	// K. MAIN BLOCKING LOOP
	for {
		sig := <-sigChan
		
		if sig == syscall.SIGHUP {
			// ZERO-DOWNTIME HOT RELOAD (Menerapkan config baru tanpa memutus koneksi)
			utils.LogInfo("SIGHUP signal received: Executing Zero-Downtime Hot-Reload...")
			BootSequence() 
		} else {
			// GRACEFUL SHUTDOWN (Mati dengan elegan)
			utils.LogInfo("Shutdown Signal (%v) received. Terminating safely...", sig)
			
			// Hapus seluruh rule firewall dari kernel Linux
			firewall.Teardown()
			
			// Bersihkan PID File
			removePID()
			
			break // Keluar dari loop dan matikan aplikasi
		}
	}
	
	utils.LogInfo("Daemon Offline. System Defense Deactivated.")
}
