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

//go:build ncp11_encaya_embedded
// +build ncp11_encaya_embedded

package main

import (
	"log"

	"github.com/btcsuite/btcd/rpcclient"

	"github.com/namecoin/encaya/lookupcerts"
	"github.com/namecoin/ncrpcclient"
	"github.com/namecoin/safetlsa"
)

var lookup *lookupcerts.Lookup

func initEncaya() error {
	if lookup != nil {
		return nil
	}

	dnsAddress := "127.0.0.1"
	dnsPort := 5391
	configDir := ""

	rootCert, rootPriv, err := safetlsa.GenerateRootCA("Namecoin")
	if err != nil {
		log.Printf("ncp11: Couldn't generate root CA: %s\n", err)
		return err
	}

	namecoinCfg := &rpcclient.ConnConfig{
		Host:         "127.0.0.1",
		User:         "",
		Pass:         "",
		CookiePath:   "namecoin.cookie",
		HTTPPostMode: true, // Namecoin core only supports HTTP POST mode
		DisableTLS:   true, // Namecoin core does not provide TLS by default
	}

	namecoin, err := ncrpcclient.New(namecoinCfg, nil)
	if err != nil {
		log.Printf("ncp11: Couldn't create Namecoin RPC client: %s\n", err)
		return err
	}

	lookup, err = lookupcerts.New(dnsAddress, dnsPort, configDir, rootCert, rootPriv,
		namecoin, false)

	if err != nil {
		log.Printf("ncp11: Couldn't create Encaya: %s\n", err)
		return err
	}

	return nil
}

func lookupCerts(name string, stapled map[string]string) ([][]byte, error) {
	err := initEncaya()
	if err != nil {
		return [][]byte{}, nil
	}

	var pubSHA256, pubB64, sigs, notAfter, piDigits string

	pubSHA256, _ = stapled["pubsha256"]
	pubB64, _ = stapled["pubb64"]
	sigs, _ = stapled["sigs"]
	notAfter, _ = stapled["notafter"]
	piDigits, _ = stapled["pidigits"]

	result, err := lookup.LookupCerts(name, pubSHA256, pubB64, sigs, notAfter, piDigits)
	if err != nil {
		log.Printf("ncp11 positive: Encaya error: %s\n", err)
		return [][]byte{}, nil
	}

	return result, nil
}

type RevokeResponse struct {
	Revoked bool `json:"revoked"`
}

func isRevoked(commonName, serialHex string) (bool, error) {
	err := initEncaya()
	if err != nil {
		return false, nil
	}

	result, err := lookup.IsRevoked(commonName, serialHex)
	if err != nil {
		log.Printf("ncp11 revoke: Encaya error: %s\n", err)
		return false, nil
	}

	return result, nil
}
