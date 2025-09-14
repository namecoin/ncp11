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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
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

	entries := []x509.RevocationListEntry{}

	// BEGIN TEST CODE (Purely for test purposes, will switch to blockchain lookup later)

	odd := new(big.Int)
	odd.Mod(serial, big.NewInt(2))
	if odd.Cmp(big.NewInt(1)) == 0 {
		entry := x509.RevocationListEntry{
			SerialNumber: serial,
		}
		entries = append(entries, entry)
	}

	crlTemplate := &x509.RevocationList{
		Issuer: *issuer,
		RevokedCertificateEntries: entries,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Printf("Failed to generate private key: %v\n", err)
		return []*p11trustmod.CertificateData{}, err
	}

	crlIssuer := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Placeholder CRL Issuer",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		// TODO: calculate this properly
		SubjectKeyId: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, crlIssuer, priv)
	if err != nil {
		log.Printf("Failed to sign CRL: %v\n", err)
		return []*p11trustmod.CertificateData{}, err
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		log.Printf("Failed to parse CRL: %v\n", err)
		return []*p11trustmod.CertificateData{}, err
	}

	// END TEST CODE

	for _, entry := range crl.RevokedCertificateEntries {
		if serial.Cmp(entry.SerialNumber) == 0 {
			// Serial is in the CRL.

			if b.trace && b.traceSensitive {
				log.Printf("ncp11 revoke: Revoking cert serial 0x%s, CommonName: %s\n", serial.Text(16), issuer.CommonName)
			}

			certData := &p11trustmod.CertificateData{
				Certificate: &x509.Certificate{
					Issuer: *issuer,
					SerialNumber: serial,
				},
			}

			certData.Label = "Revoked: " + issuer.CommonName + " " + serial.Text(16)

			certData.BuiltinPolicy = false

			certData.TrustServerAuth = pkcs11.CKT_NSS_NOT_TRUSTED
			certData.TrustClientAuth = pkcs11.CKT_NSS_NOT_TRUSTED
			certData.TrustCodeSigning = pkcs11.CKT_NSS_NOT_TRUSTED
			certData.TrustEmailProtection = pkcs11.CKT_NSS_NOT_TRUSTED

			return []*p11trustmod.CertificateData{certData}, nil
		}
	}

	if b.trace && b.traceSensitive {
		log.Printf("ncp11 revoke: Unrevoking cert serial 0x%s, CommonName: %s\n", serial.Text(16), issuer.CommonName)
	}

	return []*p11trustmod.CertificateData{}, nil
}

func (b *BackendNamecoinRevoke) QueryAll() ([]*p11trustmod.CertificateData, error) {
	return []*p11trustmod.CertificateData{}, nil
}
