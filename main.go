// Copyright 2018 Namecoin Developers LGPLv3+

// Build with this makefile:
/*
NAME ?= 'libnamecoin.so'
.PHONY: ${NAME}
${NAME}:
	CGO_ENABLED=1 go build -buildmode c-shared -o ${NAME}
clean:
    rm libnamecoin.h libnamecoin.so
*/

package main

import (
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/namecoin/pkcs11mod"
)

func init() {
	backend := NewBackendNamecoin()
	if os.Getenv("DEBUG_PKCS11") != "" {
		// open log file
		mode := os.O_CREATE | os.O_APPEND | os.O_WRONLY
		f, err := os.OpenFile(filepath.Join(getBasedir(), "pkcs11mod.log"), mode, 0600)
		if err != nil {
			println("error opening debug log file:", err.Error())
			f = os.Stderr
		}
		pkcs11mod.SetLogOutput(f)
	}
	pkcs11mod.SetBackend(backend)
	log.Println("Namecoin PKCS#11 module loading")
}

func getBasedir() string {
	if appdata := os.Getenv("LOCALAPPDATA"); runtime.GOOS == "windows" && appdata != "" {
		return filepath.Join(appdata, "Namecoin")
	}
	usr, err := user.Current()
	if err != nil {
		return filepath.Join(os.Getenv("HOME"), ".namecoin")
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(usr.HomeDir, "AppData", "Roaming", "Namecoin")
	case "darwin":
		return filepath.Join(usr.HomeDir, "Library", "Namecoin")
	default:
		return filepath.Join(usr.HomeDir, ".namecoin")
	}
}

func main() {}
