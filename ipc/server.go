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
	"time"
	"raf/config"
	"raf/firewall"
	"raf/lfd"
	"raf/utils"
)

const SocketPath = "/var/run/ronin-raf.sock"

// CommandPayload merepresentasikan struktur JSON dari Web API (mainssl) & CLI
type CommandPayload struct {
	Action   string `json:"action"`
	IP       string `json:"ip"`
	Reason   string `json:"reason"`
	Port     string `json:"port"`
	Duration string `json:"duration"`
}

// StartServer menyalakan pendengar Unix Socket lokal
func StartServer(reloadCallback func()) {
	// Hapus socket lama jika tersisa akibat crash
	os.Remove(SocketPath)
	listener, err := net.Listen("unix", SocketPath)
	if err != nil {
		utils.LogError("Failed to start RAF IPC Socket: %v", err)
		return
	}
	
	// Pastikan hanya user root/sistem yang bisa mengakses socket ini
	os.Chmod(SocketPath, 0700)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil { continue }
			go handleConnection(conn, reloadCallback)
		}
	}()
	utils.LogInfo("RAF IPC Command Center listening on %s (Ready)", SocketPath)
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

		// Delegasi Eksekusi Perintah
		switch payload.Action {
		case "RELOAD":
			reloadCallback()
			conn.Write([]byte("RAF RELOAD SUCCESS: Zero-Downtime Reload Executed.\n"))

		case "STOP":
			conn.Write([]byte("RAF STOP SUCCESS: Initiating Daemon Shutdown Sequence.\n"))
			go func() {
				p, _ := os.FindProcess(os.Getpid())
				p.Signal(syscall.SIGTERM) // Kirim sinyal shutdown elegan ke diri sendiri
			}()

		case "DENY":
			// Blokir Permanen
			EnforcePermDenyLimitAndAdd(payload.IP, payload.Reason)
			firewall.DynamicAdd(payload.IP, "DENY")
			
			// [TRIGGER EMAIL ALERT] Log ini WAJIB ada agar mainssl bisa mengirim email saat block manual
			utils.LogWarn("ADMIN BAN: IP %s permanently denied via Dashboard. Reason: %s", payload.IP, payload.Reason)
			
			conn.Write([]byte(fmt.Sprintf("SUCCESS: %s permanently denied.\n", payload.IP)))

		case "ALLOW":
			// Whitelist Permanen
			appendToFile(config.AllowFile, payload.IP, payload.Reason)
			firewall.DynamicAdd(payload.IP, "ALLOW")
			conn.Write([]byte(fmt.Sprintf("SUCCESS: %s permanently whitelisted.\n", payload.IP)))

		case "IGNORE":
			// LFD Bypass / Ignore Permanen (Tetap tunduk pada firewall)
			appendToFile(config.IgnoreFile, payload.IP, payload.Reason)
			
			// Suntikkan ke RAM secara instan agar berlaku detik itu juga
			config.CoreData.Mutex.Lock()
			if utils.CheckIPType(payload.IP) == "6" {
				config.CoreData.IgnoreList6 = append(config.CoreData.IgnoreList6, payload.IP)
			} else {
				config.CoreData.IgnoreList4 = append(config.CoreData.IgnoreList4, payload.IP)
			}
			config.CoreData.Mutex.Unlock()
			
			conn.Write([]byte(fmt.Sprintf("SUCCESS: %s added to LFD Ignore List.\n", payload.IP)))

		case "REMOVE_DENY":
			removeFromFile(config.DenyFile, payload.IP)
			firewall.DynamicDel(payload.IP, "DENY")
			conn.Write([]byte(fmt.Sprintf("SUCCESS: %s removed from Perm Deny List.\n", payload.IP)))

		case "REMOVE_ALLOW":
			removeFromFile(config.AllowFile, payload.IP)
			firewall.DynamicDel(payload.IP, "ALLOW")
			conn.Write([]byte(fmt.Sprintf("SUCCESS: %s removed from Perm Allow List.\n", payload.IP)))

		case "REMOVE_IGNORE":
			// Cabut LFD Bypass
			removeFromFile(config.IgnoreFile, payload.IP)
			
			// Hapus dari RAM List
			config.CoreData.Mutex.Lock()
			config.CoreData.IgnoreList4 = removeIPFromSlice(config.CoreData.IgnoreList4, payload.IP)
			config.CoreData.IgnoreList6 = removeIPFromSlice(config.CoreData.IgnoreList6, payload.IP)
			config.CoreData.Mutex.Unlock()

			conn.Write([]byte(fmt.Sprintf("SUCCESS: %s removed from LFD Ignore List.\n", payload.IP)))

		case "UNBAN":
			lfd.ExecuteUnban(payload.IP)
			conn.Write([]byte(fmt.Sprintf("SUCCESS: LFD Temporary Ban revoked for %s\n", payload.IP)))

		case "TEMP_BAN":
			dur, err := strconv.Atoi(payload.Duration)
			if err != nil || dur <= 0 { dur = 3600 }
			reason := payload.Reason
			if payload.Port != "" { reason = fmt.Sprintf("[Port: %s] %s", payload.Port, reason) }
			
			lfd.ExecuteBan(payload.IP, reason, dur)
			conn.Write([]byte(fmt.Sprintf("SUCCESS: Temporary Ban applied on %s for %d seconds.\n", payload.IP, dur)))

		case "TEMP_ALLOW":
			dur, err := strconv.Atoi(payload.Duration)
			if err != nil || dur <= 0 { dur = 3600 }
			
			// RAM-Based Temporary Bypass (Otomatis tercabut setelah timer habis)
			go applyTemporaryAllow(payload.IP, dur)
			conn.Write([]byte(fmt.Sprintf("SUCCESS: Temporary Allow granted on %s for %d seconds.\n", payload.IP, dur)))

		case "FLUSH_TEMP":
			lfd.FlushAllTempBans()
			conn.Write([]byte("SUCCESS: All Temporary Bans have been cleared.\n"))

		case "FLUSH_DENY":
			// Wipe file dan berikan header default
			os.WriteFile(config.DenyFile, []byte("# Permanent Blacklist\n"), 0644)
			reloadCallback() // Wajib reload untuk menyapu bersih ipset kernel secara massal
			conn.Write([]byte("SUCCESS: Permanent Deny List has been completely wiped.\n"))

		case "GET_STRIKES":
			// Minta data real-time gagal login dari RAM LFD
			failures := lfd.GetActiveFailures()
			data, _ := json.Marshal(failures)
			conn.Write(append(data, '\n'))

		default:
			conn.Write([]byte("ERR: Unknown command action.\n"))
		}
	}
}

// ==============================================================================
// INTERNAL HELPERS & LOGIC
// ==============================================================================

// removeIPFromSlice adalah helper internal untuk mencabut IP dari memori Slice secara presisi
func removeIPFromSlice(slice []string, ip string) []string {
	var result []string
	for _, v := range slice {
		if v != ip {
			result = append(result, v)
		}
	}
	return result
}

// applyTemporaryAllow menyuntikkan rule allow ke Kernel dan menjadwalkan pencabutannya
func applyTemporaryAllow(ip string, durSeconds int) {
	utils.LogInfo("ADMIN ACTION: Temporary Bypass granted for %s (%d seconds)", ip, durSeconds)
	firewall.DynamicAdd(ip, "ALLOW")
	
	// Tunggu sampai waktu habis, lalu cabut
	time.Sleep(time.Duration(durSeconds) * time.Second)
	
	firewall.DynamicDel(ip, "ALLOW")
	utils.LogInfo("AUTO-EXPIRE: Temporary Bypass revoked for %s", ip)
}

// appendToFile menulis ke file secara aman dan MENCEGAH DUPLIKASI (Exact Match)
func appendToFile(path, ip, reason string) {
	if reason == "" { reason = "Manual Administrator Override" }
	reason = strings.ReplaceAll(reason, "\n", " ")
	reason = strings.ReplaceAll(reason, "\r", "")
	ip = strings.ReplaceAll(ip, "\n", "")
	ip = strings.ReplaceAll(ip, "\r", "")

	// Cek Duplikasi IP agar list tidak menumpuk
	data, err := os.ReadFile(path)
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			clean := strings.TrimSpace(line)
			if clean == "" || strings.HasPrefix(clean, "#") { continue }
			
			// Exact Match Check
			parts := strings.SplitN(clean, "#", 2)
			existingIP := strings.TrimSpace(parts[0])
			if existingIP == ip {
				utils.LogDebug("SYSTEM: Duplicate IP insertion %s blocked on %s", ip, path)
				return // Sudah ada, batalkan append
			}
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil { return }
	defer f.Close()
	f.WriteString(fmt.Sprintf("%s # %s\n", ip, reason))
}

// removeFromFile membuang baris yang memuat IP tertentu dari sebuah file secara presisi
func removeFromFile(path, ip string) {
	data, err := os.ReadFile(path)
	if err != nil { return }

	lines := strings.Split(string(data), "\n")
	var newLines []string
	
	for _, line := range lines {
		clean := strings.TrimSpace(line)
		if clean == "" { continue }
		
		// Gunakan Exact Match agar IP yang mirip tidak ikut terhapus
		parts := strings.SplitN(clean, "#", 2)
		existingIP := strings.TrimSpace(parts[0])
		if existingIP == ip { 
			continue // Lewati baris ini (Dihapus)
		}
		
		newLines = append(newLines, line)
	}
	
	// Tulis ulang file tanpa baris yang dihapus
	os.WriteFile(path, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
}

// EnforcePermDenyLimitAndAdd menambahkan IP ke Deny File sembari memastikan tidak melebihi RAM/Limit File (Sistem FIFO)
func EnforcePermDenyLimitAndAdd(ip, reason string) {
	config.CoreData.Mutex.RLock()
	limitStr := config.CoreData.Config["RAF_DENY_IP_LIMIT"]
	config.CoreData.Mutex.RUnlock()

	limit := 2000 // Default kapasitas maksimal list manual: 2000 IP
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 { limit = l }

	if reason == "" { reason = "Manual Administrator Override" }
	reason = strings.ReplaceAll(reason, "\n", " ")
	ip = strings.ReplaceAll(ip, "\n", "")

	data, err := os.ReadFile(config.DenyFile)
	if err != nil {
		// Jika file belum ada, tulis langsung
		appendToFile(config.DenyFile, ip, reason)
		return
	}

	lines := strings.Split(string(data), "\n")
	var ipLines []string
	var headerLines []string
	ipExists := false 

	// Pisahkan header komentar (yang diawali # di depan baris) dan IP
	for _, line := range lines {
		clean := strings.TrimSpace(line)
		if clean == "" { continue }
		if strings.HasPrefix(clean, "#") { 
			headerLines = append(headerLines, line)
		} else { 
			// Cek duplikasi dengan Exact Match
			parts := strings.SplitN(clean, "#", 2)
			if strings.TrimSpace(parts[0]) == ip {
				ipExists = true
			}
			ipLines = append(ipLines, line) 
		}
	}

	// Batalkan proses penambahan ke disk jika IP sudah terdaftar
	if ipExists {
		utils.LogDebug("SYSTEM: Duplicate IP insertion %s blocked on Perm Deny List", ip)
		return
	}

	// Jika file penuh (atau akan penuh dengan masuknya IP ini)
	if len(ipLines) >= limit {
		// Hitung seberapa banyak harus dibuang dari atas (paling lama)
		diff := (len(ipLines) - limit) + 1
		pruned := ipLines[:diff]
		kept := ipLines[diff:]

		// Cabut IP yang dibuang dari tabel Kernel secara langsung
		for _, pLine := range pruned {
			parts := strings.SplitN(pLine, " ", 2) // Handle format IP yang dipisah spasi/komentar
			prunedIP := strings.TrimSpace(parts[0])
			go firewall.DynamicDel(prunedIP, "DENY")
			utils.LogWarn("LIMIT PRUNE: %s removed from Permanent Deny (Exceeds %d Max Limit)", prunedIP, limit)
		}

		// Rangkai ulang file: [Header] + [IP yang Disimpan]
		var newContent []string
		newContent = append(newContent, headerLines...)
		newContent = append(newContent, kept...)
		
		// Tulis file bersih
		os.WriteFile(config.DenyFile, []byte(strings.Join(newContent, "\n")+"\n"), 0644)
	}

	// Setelah kapasitas aman, tambahkan IP baru di urutan paling bawah
	appendToFile(config.DenyFile, ip, reason)
}
