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

//go:build !ncp11_encaya_embedded
// +build !ncp11_encaya_embedded

package main

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

func lookupCerts(name string, stapled map[string]string) ([][]byte, error) {
	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}

	postArgs := url.Values{}
	postArgs.Set("domain", name)

	// Plumb stapled data from Subject Serial Number to Encaya
	for stapledKey, stapledValue := range stapled {
		postArgs.Set(stapledKey, stapledValue)
	}

	// TODO: Use Unix domain socket
	response, err := netClient.PostForm("http://127.127.127.127/lookup", postArgs)
	if err != nil {
		log.Printf("ncp11 positive: Error POSTing to Encaya: %s\n", err)
		return [][]byte{}, nil
	}

	buf, err := io.ReadAll(response.Body)
	if err != nil {
		log.Printf("ncp11 positive: Error reading response from Encaya: %s\n", err)
		return [][]byte{}, nil
	}

	err = response.Body.Close()
	if err != nil {
		log.Printf("ncp11 positive: Error closing response from Encaya: %s\n", err)
		return [][]byte{}, nil
	}

	resultCerts := [][]byte{}

	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		resultCerts = append(resultCerts, block.Bytes)
	}

	return resultCerts, nil
}

type RevokeResponse struct {
	Revoked bool `json:"revoked"`
}

func isRevoked(commonName, serialHex string) (bool, error) {
	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}

	postArgs := url.Values{}
	postArgs.Set("domain", commonName)
	postArgs.Set("serhex", serialHex)

	// TODO: Use Unix domain socket
	response, err := netClient.PostForm("http://127.127.127.127/revoked", postArgs)
	if err != nil {
		log.Printf("ncp11 revoke: Error POSTing to Encaya: %s\n", err)
		return false, nil
	}

	buf, err := io.ReadAll(response.Body)
	if err != nil {
		log.Printf("ncp11 revoke: Error reading response from Encaya: %s\n", err)
		return false, nil
	}

	err = response.Body.Close()
	if err != nil {
		log.Printf("ncp11 revoke: Error closing response from Encaya: %s\n", err)
		return false, nil
	}

	var responseParsed RevokeResponse

	err = json.Unmarshal(buf, &responseParsed)
	if err != nil {
		log.Printf("ncp11 revoke: Error unmarshaling response from Encaya: %s\n", err)
		return false, nil
	}

	return responseParsed.Revoked, nil
}
