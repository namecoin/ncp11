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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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

type BackendNamecoinPositive struct {
	trace          bool
	traceSensitive bool
	builtin        bool
}

func NewBackendNamecoinPositive() (p11trustmod.Backend, error) {
	// Default to false because builtin status causes Certificate Transparency
	// errors in Firefox 135+. If we start getting reports of other TLS clients
	// that prefer true, we can maybe try user-agent sniffing.
	builtin := false;
	if os.Getenv("NCP11_BUILTIN_FORCE") == "0" {
		builtin = false;
	} else if os.Getenv("NCP11_BUILTIN_FORCE") == "1" {
		builtin = true;
	}

	return &BackendNamecoinPositive{
		trace:          os.Getenv("NCP11_TRACE") == "1",
		traceSensitive: os.Getenv("NCP11_TRACE_SENSITIVE") == "1",
		builtin: builtin,
	}, nil
}

func (b *BackendNamecoinPositive) Info() (pkcs11.SlotInfo, error) {
	slotInfo := pkcs11.SlotInfo{
		SlotDescription: "Namecoin TLS Positive Certificate Trust",
		ManufacturerID:  "The Namecoin Project",
		Flags:           pkcs11.CKF_TOKEN_PRESENT,
		HardwareVersion: ncp11Version,
		FirmwareVersion: ncp11Version,
	}

	return slotInfo, nil
}

func (b *BackendNamecoinPositive) TokenInfo() (pkcs11.TokenInfo, error) {
	tokenInfo := pkcs11.TokenInfo{
		Label:              "Namecoin TLS Pos Cert Trust",
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

func (b *BackendNamecoinPositive) IsBuiltinRootList() (bool, error) {
	return b.builtin, nil
}

func (b *BackendNamecoinPositive) IsTrusted() (bool, error) {
	return true, nil
}

func (b *BackendNamecoinPositive) QueryCertificate(cert *x509.Certificate) ([]*p11trustmod.CertificateData, error) {
	results, err := b.QuerySubject(&cert.Subject)
	if err != nil {
		return nil, err
	}

	issuerResults, err := b.QueryIssuerSerial(&cert.Issuer, cert.SerialNumber)
	if err != nil {
		return nil, err
	}

	results = append(results, issuerResults...)

	return results, nil
}

func (b *BackendNamecoinPositive) QuerySubject(subject *pkix.Name) ([]*p11trustmod.CertificateData, error) {
	return b.queryPkixName(subject)
}

func (b *BackendNamecoinPositive) QueryIssuerSerial(issuer *pkix.Name, serial *big.Int) ([]*p11trustmod.CertificateData, error) {
	return b.queryPkixName(issuer)
}

func (b *BackendNamecoinPositive) QueryAll() ([]*p11trustmod.CertificateData, error) {
	results, err := b.queryCommonName("Namecoin Root CA", nil)
	if err != nil {
		return nil, err
	}

	tldCAs, err := b.queryCommonName(".bit TLD CA", nil)
	if err != nil {
		return nil, err
	}

	results = append(results, tldCAs...)

	return results, nil
}

func (b *BackendNamecoinPositive) queryPkixName(name *pkix.Name) ([]*p11trustmod.CertificateData, error) {
	if strings.HasPrefix(name.SerialNumber, "Namecoin TLS Certificate") {
		stapled := map[string]string{}

		stapledHeader := "Namecoin TLS Certificate\n\nStapled: "

		if name.SerialNumber == "Namecoin TLS Certificate" {
			stapled = nil
		} else if strings.HasPrefix(name.SerialNumber, stapledHeader) {
			stapledStr := strings.TrimPrefix(name.SerialNumber, stapledHeader)

			err := json.Unmarshal([]byte(stapledStr), &stapled)
			if err != nil {
				if b.trace && b.traceSensitive {
					log.Printf("ncp11: PKIX SerialNumber stapled data failed to unmarshal (%s), CommonName: %s\n", err, name.CommonName)
				}
				return []*p11trustmod.CertificateData{}, nil
			}
		} else {
			if b.trace && b.traceSensitive {
				log.Printf("ncp11: PKIX SerialNumber had unexpected form, CommonName: %s\n", name.CommonName)
			}
			return []*p11trustmod.CertificateData{}, nil
		}

		if b.trace && b.traceSensitive {
			log.Printf("ncp11: PKIX SerialNumber matched handler whitelist, CommonName: %s\n", name.CommonName)
		}

		return b.queryCommonName(name.CommonName, stapled)
	}

	return []*p11trustmod.CertificateData{}, nil
}

func (b *BackendNamecoinPositive) queryCommonName(name string, stapled map[string]string) ([]*p11trustmod.CertificateData, error) {
	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}

	postArgs := url.Values{}
	postArgs.Set("domain", name)

	// Plumb stapled data from Subject Serial Number to Encaya
	if stapled != nil {
		for stapledKey, stapledValue := range stapled {
			postArgs.Set(stapledKey, stapledValue)
		}
	}

	if b.trace && b.traceSensitive {
		log.Printf("ncp11: Querying Encaya for: %s\n", name)
	}

	// TODO: Use Unix domain socket
	response, err := netClient.PostForm("http://127.127.127.127/lookup", postArgs)
	if err != nil {
		log.Printf("ncp11: Error POSTing to Encaya: %s\n", err)
		return []*p11trustmod.CertificateData{}, nil
	}

	buf, err := io.ReadAll(response.Body)
	if err != nil {
		log.Printf("ncp11: Error reading response from Encaya: %s\n", err)
		return []*p11trustmod.CertificateData{}, nil
	}

	err = response.Body.Close()
	if err != nil {
		log.Printf("ncp11: Error closing response from Encaya: %s\n", err)
		return []*p11trustmod.CertificateData{}, nil
	}

	results := []*p11trustmod.CertificateData{}

	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		certData := &p11trustmod.CertificateData{
			Certificate: cert,
		}

		fingerprintArray := sha256.Sum256(cert.Raw)
		hexFingerprint := strings.ToUpper(hex.EncodeToString(fingerprintArray[:]))

		certData.Label = cert.Subject.CommonName + " " + hexFingerprint

		if b.trace && b.traceSensitive {
			log.Printf("ncp11: Queried for %s, got: %s\n", name, cert.Subject.CommonName)
		}

		if cert.Subject.CommonName == "Namecoin Root CA" {
			if b.trace && b.traceSensitive {
				log.Printf("ncp11: Queried for %s, marking as trusted: %s\n", name, cert.Subject.CommonName)
			}

			certData.BuiltinPolicy = b.builtin

			// Only set trust attributes for CA's controlled by Encaya.
			certData.TrustServerAuth = pkcs11.CKT_NSS_TRUSTED_DELEGATOR
			certData.TrustClientAuth = pkcs11.CKT_NSS_NOT_TRUSTED
			certData.TrustCodeSigning = pkcs11.CKT_NSS_NOT_TRUSTED
			certData.TrustEmailProtection = pkcs11.CKT_NSS_NOT_TRUSTED
		} else {
			if b.trace && b.traceSensitive {
				log.Printf("ncp11: Queried for %s, marking as neutral: %s\n", name, cert.Subject.CommonName)
			}

			certData.BuiltinPolicy = false
		}

		results = append(results, certData)
	}

	if b.trace && b.traceSensitive {
		log.Printf("ncp11: Returned %d certificates for: %s\n", len(results), name)
	}

	return results, nil
}
