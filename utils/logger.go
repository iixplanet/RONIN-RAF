// file: utils/logger.go
package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var Logger *log.Logger

func InitLogger(logFile string) {
	os.MkdirAll(filepath.Dir(logFile), 0755)
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to open log file %s: %v\n", logFile, err)
		os.Exit(1)
	}
	Logger = log.New(file, "[RAF] ", log.Ldate|log.Ltime)
}

func LogInfo(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	fmt.Println("\033[1;32m[INFO]\033[0m", msg) // Green text for terminal
	if Logger != nil {
		Logger.Println("INFO:", msg)
	}
}

func LogWarn(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	fmt.Println("\033[1;33m[WARN]\033[0m", msg) // Yellow text for terminal
	if Logger != nil {
		Logger.Println("WARN:", msg)
	}
}

func LogError(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	fmt.Println("\033[1;31m[ERROR]\033[0m", msg) // Red text for terminal
	if Logger != nil {
		Logger.Println("ERROR:", msg)
	}
}