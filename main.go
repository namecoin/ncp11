// ncp11
// Copyright (C) 2018-2022  Namecoin Developers
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
	"github.com/namecoin/pkcs11mod/p11mod"
)

func init() {
	module, err := NewModuleNamecoin()

	p11mod.SetBackend(module, err)
}

func main() {}
