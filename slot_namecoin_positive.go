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

package main

import (
	"github.com/miekg/pkcs11/p11"

	"github.com/namecoin/pkcs11mod/p11trustmod"
)

func NewSlotNamecoinPositive() (p11.Slot, error) {
	backend, err := NewBackendNamecoinPositive()
	if err != nil {
		return nil, err
	}

	return p11trustmod.Slot(backend, 0), nil
}
