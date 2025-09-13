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
	"log"
	"math/big"
	"os"
	"strings"

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

func (b *BackendNamecoinRevoke) QueryIssuerSerial(issuer *pkix.Name, serial *big.Int) ([]*p11trustmod.CertificateData, error) {
	if issuer == nil || serial == nil {
		return []*p11trustmod.CertificateData{}, nil
	}

	if !strings.HasPrefix(issuer.SerialNumber, "Namecoin TLS Certificate") {
		return []*p11trustmod.CertificateData{}, nil
	}

	// Purely for test purposes, will switch to blockchain lookup later

	odd := new(big.Int)
	odd.Mod(serial, big.NewInt(2))
	if odd.Cmp(big.NewInt(1)) == 0 {
		if b.trace && b.traceSensitive {
			log.Printf("ncp11: Revoking cert serial %s, CommonName: %s\n", serial.String(), issuer.CommonName)
		}

		certData := &p11trustmod.CertificateData{
			Certificate: &x509.Certificate{
				Issuer: *issuer,
				SerialNumber: serial,
			},
		}

		certData.Label = "Revoked: " + issuer.CommonName + " " + serial.String()

		certData.BuiltinPolicy = false

		certData.TrustServerAuth = pkcs11.CKT_NSS_NOT_TRUSTED
		certData.TrustClientAuth = pkcs11.CKT_NSS_NOT_TRUSTED
		certData.TrustCodeSigning = pkcs11.CKT_NSS_NOT_TRUSTED
		certData.TrustEmailProtection = pkcs11.CKT_NSS_NOT_TRUSTED

		return []*p11trustmod.CertificateData{certData}, nil
	}

	if b.trace && b.traceSensitive {
		log.Printf("ncp11: Unrevoked cert serial %s, CommonName: %s\n", serial.String(), issuer.CommonName)
	}

	return []*p11trustmod.CertificateData{}, nil
}

func (b *BackendNamecoinRevoke) QueryAll() ([]*p11trustmod.CertificateData, error) {
	return []*p11trustmod.CertificateData{}, nil
}
