// file: utils/logger.go
package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var Logger *log.Logger
var LogFilePath string

// ClearLog mengosongkan isi file log (truncate)
func ClearLog(path string) {
	os.WriteFile(path, []byte(""), 0644)
}

// CheckLogSize merotasi log jika melebihi 5MB agar UI tidak hang
func CheckLogSize() {
	if stat, err := os.Stat(LogFilePath); err == nil {
		if stat.Size() > 5*1024*1024 { // 5 Megabytes
			ClearLog(LogFilePath)
			LogInfo("SYSTEM MAINTENACE: Log file exceeded 5MB and was auto-truncated.")
		}
	}
}

func InitLogger(logFile string) {
	LogFilePath = logFile
	os.MkdirAll(filepath.Dir(logFile), 0755)
	
	// Bersihkan log setiap kali daemon di-restart dari nol
	ClearLog(logFile)
	
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to open log file %s: %v\n", logFile, err)
		os.Exit(1)
	}
	Logger = log.New(file, "", log.Ldate|log.Ltime) // Hapus prefix [RAF] agar rapi di web
}

func LogInfo(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	fmt.Println("\033[1;32m[INFO]\033[0m", msg)
	if Logger != nil { CheckLogSize(); Logger.Println("INFO:", msg) }
}

func LogWarn(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	fmt.Println("\033[1;33m[WARN]\033[0m", msg)
	if Logger != nil { CheckLogSize(); Logger.Println("WARN:", msg) }
}

func LogError(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	fmt.Println("\033[1;31m[ERROR]\033[0m", msg)
	if Logger != nil { CheckLogSize(); Logger.Println("ERROR:", msg) }
}
