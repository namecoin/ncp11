// Copyright 2018 Namecoin Developers LGPLv3+

package main

const (
	// Tor Browser on Windows targets sets the working directory to the Tor
	// Browser directory, so we check there for a CKBI library.  It is
	// unknown whether this heuristic works on other OS's or other
	// browsers.
	filenameCKBIReplaceSelf = "./nssckbi.dll"
	filenameCKBIReplaceTarget = "./nssckbi-namecoin-target.dll"

	// Used for system-wide applications.  TODO: This needs to be modified
	// to work on Windows.  However, it is unknown whether there actually
	// exist any Windows applications that use a system-wide NSS
	// installation.
	filenameCKBIAlongsideTarget = "/usr/local/namecoin/nssckbi-namecoin-target.dll"
)
