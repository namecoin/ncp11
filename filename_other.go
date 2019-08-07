// Copyright 2018 Namecoin Developers LGPLv3+

// +build !darwin,!windows

package main

import (
	"os"
)

var (
	// Tor Browser's "start-tor-browser" script on GNU/Linux targets sets
	// $HOME to the Tor Browser directory, so we check there for a CKBI
	// library.  This heuristic doesn't work on Windows.
	filenameCKBIReplaceSelf = os.Getenv("HOME") + "/libnssckbi.so"
	filenameCKBIReplaceTarget = os.Getenv("HOME") + "/libnssckbi-namecoin-target.so"

	// Used for system-wide applications
	filenameCKBIAlongsideTarget = "/usr/local/namecoin/libnssckbi-namecoin-target.so"
)
