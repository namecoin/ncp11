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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/pkcs11"

	"github.com/namecoin/pkcs11mod/p11trustmod"
)

type BackendNamecoinRevoke struct {
	trace          bool
	traceSensitive bool
}

func NewBackendNamecoinRevoke() (p11trustmod.Backend, error) {
	return &BackendNamecoinRevoke{
		trace:          os.Getenv("NCP11_TRACE") == "1",
		traceSensitive: os.Getenv("NCP11_TRACE_SENSITIVE") == "1",
	}, nil
}

func (b *BackendNamecoinRevoke) Info() (pkcs11.SlotInfo, error) {
	slotInfo := pkcs11.SlotInfo{
		SlotDescription: "Namecoin TLS Revocation Certificate Trust",
		ManufacturerID:  "The Namecoin Project",
		Flags:           pkcs11.CKF_TOKEN_PRESENT,
		HardwareVersion: ncp11Version,
		FirmwareVersion: ncp11Version,
	}

	return slotInfo, nil
}

func (b *BackendNamecoinRevoke) TokenInfo() (pkcs11.TokenInfo, error) {
	tokenInfo := pkcs11.TokenInfo{
		Label:              "Namecoin TLS Revoke Cert Trust",
		ManufacturerID:     "The Namecoin Project",
		Model:              "ncp11",
		SerialNumber:       "1",
		Flags:              pkcs11.CKF_WRITE_PROTECTED,
		MaxSessionCount:    pkcs11.CK_EFFECTIVELY_INFINITE,
		SessionCount:       pkcs11.CK_UNAVAILABLE_INFORMATION,
		MaxRwSessionCount:  pkcs11.CK_UNAVAILABLE_INFORMATION,
		RwSessionCount:     pkcs11.CK_UNAVAILABLE_INFORMATION,
		MaxPinLen:          ^uint(0), // highest possible uint
		MinPinLen:          0,
		TotalPublicMemory:  pkcs11.CK_UNAVAILABLE_INFORMATION,
		FreePublicMemory:   pkcs11.CK_UNAVAILABLE_INFORMATION,
		TotalPrivateMemory: pkcs11.CK_UNAVAILABLE_INFORMATION,
		FreePrivateMemory:  pkcs11.CK_UNAVAILABLE_INFORMATION,
		HardwareVersion:    ncp11Version,
		FirmwareVersion:    ncp11Version,
		UTCTime:            "",
	}

	return tokenInfo, nil
}

func (b *BackendNamecoinRevoke) IsBuiltinRootList() (bool, error) {
	return false, nil
}

func (b *BackendNamecoinRevoke) IsTrusted() (bool, error) {
	return true, nil
}

func (b *BackendNamecoinRevoke) QueryCertificate(cert *x509.Certificate) ([]*p11trustmod.CertificateData, error) {
	return b.QueryIssuerSerial(&cert.Issuer, cert.SerialNumber)
}

func (b *BackendNamecoinRevoke) QuerySubject(subject *pkix.Name) ([]*p11trustmod.CertificateData, error) {
	return []*p11trustmod.CertificateData{}, nil
}

type RevokeResponse struct {
	Revoked bool `json:"revoked"`
}

func (b *BackendNamecoinRevoke) QueryIssuerSerial(issuer *pkix.Name, serial *big.Int) ([]*p11trustmod.CertificateData, error) {
	if issuer == nil || serial == nil {
		return []*p11trustmod.CertificateData{}, nil
	}

	if !strings.HasPrefix(issuer.SerialNumber, "Namecoin TLS Certificate") {
		return []*p11trustmod.CertificateData{}, nil
	}

	if b.trace && b.traceSensitive {
		log.Printf("ncp11 revoke: PKIX SerialNumber matched handler whitelist, CommonName: %s\n", issuer.CommonName)
	}

	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}

	postArgs := url.Values{}
	postArgs.Set("domain", issuer.CommonName)

	serialHex := serial.Text(16)
	for len(serialHex) < 2*20 {
		serialHex = "0" + serialHex
	}

	postArgs.Set("serhex", serialHex)

	if b.trace && b.traceSensitive {
		log.Printf("ncp11 revoke: Querying Encaya for: %s\n", issuer.CommonName)
	}

	// TODO: Use Unix domain socket
	response, err := netClient.PostForm("http://127.127.127.127/revoked", postArgs)
	if err != nil {
		log.Printf("ncp11 revoke: Error POSTing to Encaya: %s\n", err)
		return []*p11trustmod.CertificateData{}, nil
	}

	buf, err := io.ReadAll(response.Body)
	if err != nil {
		log.Printf("ncp11 revoke: Error reading response from Encaya: %s\n", err)
		return []*p11trustmod.CertificateData{}, nil
	}

	err = response.Body.Close()
	if err != nil {
		log.Printf("ncp11 revoke: Error closing response from Encaya: %s\n", err)
		return []*p11trustmod.CertificateData{}, nil
	}

	var responseParsed RevokeResponse

	err = json.Unmarshal(buf, &responseParsed)
	if err != nil {
		log.Printf("ncp11 revoke: Error unmarshaling response from Encaya: %s\n", err)
		return []*p11trustmod.CertificateData{}, nil
	}

	isRevoked := responseParsed.Revoked

	if !isRevoked {
		if b.trace && b.traceSensitive {
			log.Printf("ncp11 revoke: Unrevoking cert serial 0x%s, CommonName: %s\n", serialHex, issuer.CommonName)
		}

		return []*p11trustmod.CertificateData{}, nil
	}

	// Cert is revoked.

	if b.trace && b.traceSensitive {
		log.Printf("ncp11 revoke: Revoking cert serial 0x%s, CommonName: %s\n", serialHex, issuer.CommonName)
	}

	certData := &p11trustmod.CertificateData{
		Certificate: &x509.Certificate{
			Issuer: *issuer,
			SerialNumber: serial,
		},
	}

	certData.Label = "Revoked: " + issuer.CommonName + " " + serialHex

	certData.BuiltinPolicy = false

	certData.TrustServerAuth = pkcs11.CKT_NSS_NOT_TRUSTED
	certData.TrustClientAuth = pkcs11.CKT_NSS_NOT_TRUSTED
	certData.TrustCodeSigning = pkcs11.CKT_NSS_NOT_TRUSTED
	certData.TrustEmailProtection = pkcs11.CKT_NSS_NOT_TRUSTED

	return []*p11trustmod.CertificateData{certData}, nil
}

func (b *BackendNamecoinRevoke) QueryAll() ([]*p11trustmod.CertificateData, error) {
	return []*p11trustmod.CertificateData{}, nil
}
