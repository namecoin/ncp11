// ncp11
// Copyright (C) 2018-2025 Namecoin Developers
//
// ncp11 is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// ncp11 is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with ncp11; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

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
