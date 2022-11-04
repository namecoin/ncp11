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

package main

import (
	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

var (
	// TODO: Detect Library version from Git tag?
	ncp11Version = pkcs11.Version{0, 0}
)

type ModuleNamecoin struct {
}

func NewModuleNamecoin() (p11.Module, error) {
	return &ModuleNamecoin{}, nil
}

func (b *ModuleNamecoin) Destroy() {
}

func (b *ModuleNamecoin) Info() (pkcs11.Info, error) {
	info := pkcs11.Info{
		// TODO: Bump to newer CK version?
		CryptokiVersion:    pkcs11.Version{2, 20},
		ManufacturerID:     "The Namecoin Project",
		Flags:              0,
		LibraryDescription: "Namecoin TLS Certificate Trust",
		LibraryVersion:     ncp11Version,
	}
	return info, nil
}

func (b *ModuleNamecoin) Slots() ([]p11.Slot, error) {
	positive, err := NewSlotNamecoinPositive()
	if err != nil {
		return []p11.Slot{}, err
	}

	slots := []p11.Slot{positive}

	return slots, nil
}
