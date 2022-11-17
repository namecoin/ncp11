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

//go:build ignore

package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"log"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/pkcs11"

	"github.com/namecoin/pkcs11mod"
)

type certObject struct {
	cert *x509.Certificate
	class uint
}

type session struct {
	backend *BackendNamecoin
	slotID uint
	ckbiSessionHandle pkcs11.SessionHandle
	isDistrustSlot bool
	isRestrictSlot bool
	certs chan *certObject
	domain string
	template []*pkcs11.Attribute
	objects []*certObject // The ObjectHandle is calculated as the index in this slice + 1
	// TODO: make object handles unique per token, not just unique per session.
	// TODO: delete object handles that are outdated, so that we can be guaranteed that revocation works
}

type BackendNamecoin struct {
	manufacturer string
	description string
	version pkcs11.Version
	slotPositive uint
	slotNegativeDistrust []uint // index is Namecoin slot - 1; value is CKBI slot
	slotNegativeRestrict []uint // index is Namecoin slot - len(slotNegativeDistrust) - 1; value is CKBI slot
	sessions map[pkcs11.SessionHandle]*session
	sessionMutex sync.RWMutex // Used for the sessions var
	ckbiBackend *pkcs11.Ctx
	ckbiPath string
	ckbiRestrictCert *x509.Certificate
	ckbiRestrictCertPEM string
	ckbiRestrictPrivPEM string
	enableImpersonateCKBI bool
	enableDistrustCKBI bool
	enableRestrictCKBI bool
}

func NewBackendNamecoin() *BackendNamecoin {
	ckbiPath := ""

	// Some browsers (e.g. Tor Browser) ship with their own CKBI.  We
	// detect here whether we've been launched by such a browser, in order
	// to make the CKBI proxy target the browser-specific CKBI instead of
	// the system's CKBI.
	_, torCKBIStatErr := os.Stat(filenameCKBIReplaceSelf)
	if torCKBIStatErr == nil {
		// Tor Browser detected
		ckbiPath = filenameCKBIReplaceTarget
		log.Printf("Using Tor Browser CKBI: %s", ckbiPath)
	} else {
		// Anything other than Tor Browser
		ckbiPath = filenameCKBIAlongsideTarget
		log.Printf("Using system CKBI: %s", ckbiPath)
	}

	return &BackendNamecoin{
		manufacturer: "Namecoin",
		description: "Namecoin TLS Certificate Trust",
		version: pkcs11.Version{0, 0},
		slotPositive: 0,
		sessions: map[pkcs11.SessionHandle]*session{},
		ckbiPath: ckbiPath, // TODO: make this a configurable option
		enableImpersonateCKBI: true, // TODO: make this a configurable option
		enableDistrustCKBI: false, // TODO: make this a configurable option
		enableRestrictCKBI: true, // TODO: make this a configurable option
	}
}

func (b *BackendNamecoin) Initialize() error {
	if b.enableDistrustCKBI || b.enableRestrictCKBI {
		if b.ckbiBackend == nil {
			b.ckbiBackend = pkcs11.New(b.ckbiPath)
			if b.ckbiBackend == nil {
				log.Printf("Failed to open proxy CKBI backend %s", b.ckbiPath)
				return pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
			}
		}

		err := b.ckbiBackend.Initialize()
		if err != nil {
			log.Printf("Error initializing proxied CKBI backend: %s\n", err)
			return err
		}
	}

	if b.enableRestrictCKBI {
		b.obtainRestrictCA()
	}

	log.Println("Namecoin pkcs11 backend initialized")
	return nil
}

func (b *BackendNamecoin) Finalize() error {
	if b.enableDistrustCKBI || b.enableRestrictCKBI {
		err := b.ckbiBackend.Finalize()
		if err != nil {
			log.Printf("Error finalizing proxied CKBI backend: %s\n", err)
			return err
		}
	}

	log.Println("Namecoin pkcs11 backend closing")
	return nil
}

func (b *BackendNamecoin) GetInfo() (pkcs11.Info, error) {
	info := pkcs11.Info{
		CryptokiVersion:    pkcs11.Version{2, 20},
		ManufacturerID:     b.manufacturer,
		Flags:              0,
		LibraryDescription: b.description,
		LibraryVersion:     b.version,
	}
	return info, nil
}

func (b *BackendNamecoin) GetSlotList(tokenPresent bool) ([]uint, error) {
	// Only a single positive slot exists.
	result := []uint{b.slotPositive}

	b.slotNegativeDistrust = []uint{}
	b.slotNegativeRestrict = []uint{}

	if b.enableDistrustCKBI {
		ckbiDistrustResult, err := b.ckbiBackend.GetSlotList(tokenPresent)
		if err != nil {
			return []uint{}, err
		}

		for _, distrustSlot := range ckbiDistrustResult {
			b.slotNegativeDistrust = append(b.slotNegativeDistrust, distrustSlot)
			result = append(result, uint(len(b.slotNegativeDistrust)))
		}
	}
	if b.enableRestrictCKBI {
		ckbiRestrictResult, err := b.ckbiBackend.GetSlotList(tokenPresent)
		if err != nil {
			return []uint{}, err
		}

		for _, restrictSlot := range ckbiRestrictResult {
			b.slotNegativeRestrict = append(b.slotNegativeRestrict, restrictSlot)
			result = append(result, uint(len(b.slotNegativeDistrust) + len(b.slotNegativeRestrict)))
		}
	}

	return result, nil
}

func (b *BackendNamecoin) toCKBISlotID(slotID uint) (uint, error) {
	if slotID == b.slotPositive {
		log.Printf("toCKBISlotID: slotID == b.slotPositive\n")
		return 0, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
	}

	slotID -= 1

	if slotID < uint(len(b.slotNegativeDistrust)) {
		return b.slotNegativeDistrust[slotID], nil
	}

	slotID -= uint(len(b.slotNegativeDistrust))

	if slotID < uint(len(b.slotNegativeRestrict)) {
		return b.slotNegativeRestrict[slotID], nil
	}

	log.Printf("toCKBISlotID: slotID out of bounds\n")
	return 0, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
}

func (b *BackendNamecoin) GetSlotInfo(slotID uint) (pkcs11.SlotInfo, error) {
	if slotID != b.slotPositive {
		ckbiSlotID, err := b.toCKBISlotID(slotID)
		if err != nil {
			log.Printf("GetSlotInfo: CKR_SLOT_ID_INVALID\n")
			return pkcs11.SlotInfo{}, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
		}

		ckbiSlotInfo, err := b.ckbiBackend.GetSlotInfo(ckbiSlotID)
		if err != nil {
			return ckbiSlotInfo, err
		}

		isDistrustSlot := slotID - 1 < uint(len(b.slotNegativeDistrust))
		isRestrictSlot := !isDistrustSlot

		if isDistrustSlot {
			ckbiSlotInfo.SlotDescription = "Distrust " + ckbiSlotInfo.SlotDescription
		} else if isRestrictSlot {
			ckbiSlotInfo.SlotDescription = "Restrict " + ckbiSlotInfo.SlotDescription
		}

		return ckbiSlotInfo, nil
	}

	slotInfo := pkcs11.SlotInfo{
		SlotDescription: b.description,
		ManufacturerID: b.manufacturer,
		Flags: pkcs11.CKF_TOKEN_PRESENT,
		HardwareVersion: b.version,
		FirmwareVersion: b.version,
	}

	return slotInfo, nil
}

func (b *BackendNamecoin) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	if slotID != b.slotPositive {
		ckbiSlotID, err := b.toCKBISlotID(slotID)
		if err != nil {
			log.Printf("GetTokenInfo: CKR_SLOT_ID_INVALID\n")
			return pkcs11.TokenInfo{}, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
		}

		ckbiTokenInfo, err := b.ckbiBackend.GetTokenInfo(ckbiSlotID)
		if err != nil {
			return ckbiTokenInfo, err
		}

		isDistrustSlot := slotID - 1 < uint(len(b.slotNegativeDistrust))
		isRestrictSlot := !isDistrustSlot

		if isDistrustSlot {
			ckbiTokenInfo.Label = "Distrust " + ckbiTokenInfo.Label
		} else if isRestrictSlot {
			ckbiTokenInfo.Label = "Restrict " + ckbiTokenInfo.Label
		}

		return ckbiTokenInfo, nil
	}

	tokenInfo := pkcs11.TokenInfo{
		Label: b.description,
		ManufacturerID: b.manufacturer,
		Model: "ncp11",
		SerialNumber: "1",
		Flags: pkcs11.CKF_WRITE_PROTECTED,
		MaxSessionCount: 0, // CK_EFFECTIVELY_INFINITE from pkcs11 spec (not in miekg/pkcs11)
		SessionCount: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		MaxRwSessionCount: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		RwSessionCount: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		MaxPinLen: ^uint(0), // highest possible uint
		MinPinLen: 0,
		TotalPublicMemory: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		FreePublicMemory: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		TotalPrivateMemory: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		FreePrivateMemory: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		HardwareVersion: b.version,
		FirmwareVersion: b.version,
		UTCTime: "",
	}

	return tokenInfo, nil
}

func (b *BackendNamecoin) GetMechanismList(slotID uint) ([]*pkcs11.Mechanism, error) {
	// Namecoin doesn't implement any mechanisms
	return []*pkcs11.Mechanism{}, nil
}

// Only call this while b.sessionMutex is write-locked
func (b *BackendNamecoin) nextAvailableSessionHandle() pkcs11.SessionHandle {
	sessionHandle := pkcs11.SessionHandle(1)

	for {
		_, ok := b.sessions[sessionHandle]
		if !ok {
			break
		}
		sessionHandle++
	}

	return sessionHandle
}

func (b *BackendNamecoin) ckbiOpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	ckbiSlotID, err := b.toCKBISlotID(slotID)
	if err != nil {
		log.Printf("ckbiOpenSession: CKR_SLOT_ID_INVALID\n")
		return 0, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
	}

	ckbiHandle, err := b.ckbiBackend.OpenSession(ckbiSlotID, flags)
	if err != nil {
		return 0, err
	}

	isDistrustSlot := slotID - 1 < uint(len(b.slotNegativeDistrust))
	isRestrictSlot := !isDistrustSlot

	newSession := session{
		backend: b,
		slotID: slotID,
		ckbiSessionHandle: ckbiHandle,
		isDistrustSlot: isDistrustSlot,
		isRestrictSlot: isRestrictSlot,
	}

	b.sessionMutex.Lock()
	newSessionHandle := b.nextAvailableSessionHandle()
	b.sessions[newSessionHandle] = &newSession
	b.sessionMutex.Unlock()

	return newSessionHandle, nil
}

func (b *BackendNamecoin) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	if slotID != b.slotPositive {
		return b.ckbiOpenSession(slotID, flags)
	}

	if flags & pkcs11.CKF_RW_SESSION != 0 {
		// only read-only sessions are supported.
		log.Printf("OpenSession: CKR_TOKEN_WRITE_PROTECTED\n")
		return 0, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
	}
	if flags & pkcs11.CKF_SERIAL_SESSION == 0 {
		log.Printf("OpenSession: CKR_SESSION_PARALLEL_NOT_SUPPORTED\n")
		return 0, pkcs11.Error(pkcs11.CKR_SESSION_PARALLEL_NOT_SUPPORTED)
	}

	newSession := session{
		backend: b,
		slotID: b.slotPositive,
	}

	b.sessionMutex.Lock()
	newSessionHandle := b.nextAvailableSessionHandle()
	b.sessions[newSessionHandle] = &newSession
	b.sessionMutex.Unlock()

	return newSessionHandle, nil
}

func (b *BackendNamecoin) CloseSession(sh pkcs11.SessionHandle) error {
	// First we read the CKBI session ID and close the CKBI session...

	b.sessionMutex.RLock()
	s, sessionExists := b.sessions[sh]
	b.sessionMutex.RUnlock()

	if !sessionExists {
		log.Printf("CloseSession: CKR_SESSION_HANDLE_INVALID before closing CKBI\n")
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	if s.slotID != b.slotPositive {
		err := b.ckbiBackend.CloseSession(s.ckbiSessionHandle)
		if err != nil {
			log.Printf("CloseSession: error while closing CKBI\n")
			return err
		}
	}

	// Then we delete the session locally.

	b.sessionMutex.Lock()
	_, sessionExists = b.sessions[sh]
	delete(b.sessions, sh)
	b.sessionMutex.Unlock()

	if !sessionExists {
		log.Printf("CloseSession: CKR_SESSION_HANDLE_INVALID while closing local session\n")
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	return nil
}

func (b *BackendNamecoin) Login(sh pkcs11.SessionHandle, userType uint, pin string) error {
	return nil
}

func (b *BackendNamecoin) Logout(sh pkcs11.SessionHandle) error {
	return nil
}

func (b *BackendNamecoin) GetObjectSize(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) (uint, error) {
	log.Printf("GetObjectSize unimplemented\n")
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b *BackendNamecoin) GetAttributeValue(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	b.sessionMutex.RLock()
	s, sessionExists := b.sessions[sh]
	b.sessionMutex.RUnlock()

	if !sessionExists {
		log.Printf("GetAttributeValue: CKR_SESSION_HANDLE_INVALID\n")
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	// Handle CKBI proxying
	if s.slotID != b.slotPositive {
		ckbiResult, err := b.ckbiBackend.GetAttributeValue(s.ckbiSessionHandle, oh, a)
		if err != nil {
			return ckbiResult, err
		}

		shouldCrossSign := false
		originalDER := []byte{}
		originalTrust := uint(0)
		crossSignedDER := []byte{}
		var crossSignedParsed *x509.Certificate

		if s.isRestrictSlot {
			originalDER, originalTrust, err = s.getCKBIDataToCrossSign(oh)
			if err != nil {
				// This will force shouldCrossSign to false
				originalTrust = 0
			}

			shouldCrossSign = originalTrust == pkcs11.CKT_NSS_TRUSTED_DELEGATOR
			if shouldCrossSign {
				crossSignedDER = b.crossSignCKBI(originalDER)
				crossSignedParsed, err = x509.ParseCertificate(crossSignedDER)
				if err != nil {
					log.Printf("Error parsing cross-signed certificate: %s", err)
					shouldCrossSign = false
				}
			}
		}

		for i, attr := range ckbiResult {
			if attr.Type == pkcs11.CKA_LABEL && s.isDistrustSlot {
				//*ckbiResult[i] = *pkcs11.NewAttribute(attr.Type, "Distrust " + string(attr.Value))
			}

			// Distrust the original CKBI cert
			if attr.Type == pkcs11.CKA_TRUST_SERVER_AUTH && s.isDistrustSlot {
				*ckbiResult[i] = *pkcs11.NewAttribute(attr.Type, uint(pkcs11.CKT_NSS_NOT_TRUSTED))
			}

			// Only cross-sign if the original CKBI cert is a trusted root CA for TLS server auth
			if shouldCrossSign {
				if attr.Type == pkcs11.CKA_LABEL {
					// TODO: look into re-enabling this after we have better test tooling.
					//*ckbiResult[i] = *pkcs11.NewAttribute(attr.Type, "Restrict " + string(attr.Value))
				}

				// Cross-sign the original CKBI cert
				if attr.Type == pkcs11.CKA_VALUE {
					*ckbiResult[i] = *pkcs11.NewAttribute(attr.Type, crossSignedParsed.Raw)
				}

				// Use the restrict CA subject as the issuer
				if attr.Type == pkcs11.CKA_ISSUER {
					*ckbiResult[i] = *pkcs11.NewAttribute(attr.Type, crossSignedParsed.RawIssuer)
				}

				// Use the serial number from the cross-signed cert
				if attr.Type == pkcs11.CKA_SERIAL_NUMBER {
					crossSignedSerialNumber, err := asn1.Marshal(crossSignedParsed.SerialNumber)
					if err != nil {
						log.Printf("Error marshaling SerialNumber from cross-signed cert")
						continue
					}

					*ckbiResult[i] = *pkcs11.NewAttribute(attr.Type, crossSignedSerialNumber)
				}

				// Use neutral status on the cross-signed cert
				if attr.Type == pkcs11.CKA_TRUST_SERVER_AUTH {
					*ckbiResult[i] = *pkcs11.NewAttribute(attr.Type, uint(pkcs11.CKT_NSS_MUST_VERIFY_TRUST))
				}

				// Use the SHA1 hash of the cross-signed cert
				if attr.Type == pkcs11.CKA_CERT_SHA1_HASH {
					crossSignedSha1Array := sha1.Sum(crossSignedParsed.Raw)

					*ckbiResult[i] = *pkcs11.NewAttribute(attr.Type, crossSignedSha1Array[:])
				}
			}
		}

		return ckbiResult, nil
	}

	co := s.objects[oh - 1]
	cert := co.cert

	results := make([]*pkcs11.Attribute, len(a))

	hasUnknownAttr := false
	unknownAttrs := []uint{}

	for i, attr := range a {
		if attr.Type == pkcs11.CKA_CLASS {
			results[i] = pkcs11.NewAttribute(attr.Type, co.class)
		} else if attr.Type == pkcs11.CKA_TOKEN {
			results[i] = pkcs11.NewAttribute(attr.Type, true)
		} else if attr.Type == pkcs11.CKA_LABEL {
			if co.class == pkcs11.CKO_NSS_BUILTIN_ROOT_LIST {
				results[i] = pkcs11.NewAttribute(attr.Type, "Namecoin Builtin Roots")
			} else {
				fingerprintArray := sha256.Sum256(cert.Raw)
				hexFingerprint := strings.ToUpper(hex.EncodeToString(fingerprintArray[:]))

				results[i] = pkcs11.NewAttribute(attr.Type, cert.Subject.CommonName + " " + hexFingerprint)
			}
		} else if attr.Type == pkcs11.CKA_VALUE {
			results[i] = pkcs11.NewAttribute(attr.Type, cert.Raw)
		} else if attr.Type == pkcs11.CKA_CERTIFICATE_TYPE {
			results[i] = pkcs11.NewAttribute(attr.Type, pkcs11.CKC_X_509)
		} else if attr.Type == pkcs11.CKA_ISSUER {
			results[i] = pkcs11.NewAttribute(attr.Type, cert.RawIssuer)
		} else if attr.Type == pkcs11.CKA_SERIAL_NUMBER {
			certSerialNumber, err := asn1.Marshal(cert.SerialNumber)
			if err != nil {
				log.Printf("Error marshaling SerialNumber from dehydrated cert")
				hasUnknownAttr = true
				unknownAttrs = append(unknownAttrs, attr.Type)
			}

			results[i] = pkcs11.NewAttribute(attr.Type, certSerialNumber)
		} else if attr.Type == pkcs11.CKA_SUBJECT {
			results[i] = pkcs11.NewAttribute(attr.Type, cert.RawSubject)
		} else if attr.Type == pkcs11.CKA_ID {
			results[i] = pkcs11.NewAttribute(attr.Type, "0")
		} else if attr.Type == pkcs11.CKA_NSS_MOZILLA_CA_POLICY {
			if b.enableImpersonateCKBI {
				results[i] = pkcs11.NewAttribute(attr.Type, true)
			} else {
				log.Println("GetAttributeValue requested CKA_NSS_MOZILLA_CA_POLICY while CKBI impersonation is disabled")
				results[i] = pkcs11.NewAttribute(attr.Type, false)
			}
		} else if attr.Type == pkcs11.CKA_TRUST_SERVER_AUTH {
			if strings.HasSuffix(cert.Subject.CommonName, " Root CA") {
				// This is a root CA; it's used as a trust
				// anchor.

				// CKT_NSS_TRUSTED_DELEGATOR should be
				// equivalent to the "C" trust flag in NSS
				// certutil.
				// TODO: Actually test that it can't be used as
				// an end-entity cert.

				results[i] = pkcs11.NewAttribute(attr.Type, uint(pkcs11.CKT_NSS_TRUSTED_DELEGATOR))
			} else if strings.HasSuffix(cert.Subject.CommonName, " TLD CA") {
				// This is a CA that has a name constraint
				// whitelisting a specific TLD.

				// This cert isn't a trust anchor; it's instead
				// signed by a root CA.

				// CKT_NSS_MUST_VERIFY_TRUST indicates that
				// it should never be used as a trust anchor,
				// but also isn't blacklisted.
				// TODO: Actually test that it behaves this
				// way.

				results[i] = pkcs11.NewAttribute(attr.Type, uint(pkcs11.CKT_NSS_MUST_VERIFY_TRUST))
			} else if strings.HasSuffix(cert.Subject.CommonName, " Domain CA") {
				// This is a CA that has a name constraint
				// whitelisting a specific domain name.

				// This cert isn't a trust anchor; it's instead
				// signed by a TLD CA or a root CA.

				// CKT_NSS_MUST_VERIFY_TRUST indicates that
				// it should never be used as a trust anchor,
				// but also isn't blacklisted.
				// TODO: Actually test that it behaves this
				// way.

				results[i] = pkcs11.NewAttribute(attr.Type, uint(pkcs11.CKT_NSS_MUST_VERIFY_TRUST))
			} else {
				// This is an end-entity cert.

				// CKT_NSS_TRUSTED should be equivalent to the
				// "P" trust flag in NSS certutil.
				// TODO: actually test that CKT_NSS_TRUSTED
				// doesn't allow it to act as a CA.

				results[i] = pkcs11.NewAttribute(attr.Type, uint(pkcs11.CKT_NSS_TRUSTED))
			}
		} else if attr.Type == pkcs11.CKA_TRUST_CLIENT_AUTH {
			// CKT_NSS_NOT_TRUSTED should be equivalent to
			// blacklisting the cert.
			// TODO: actually test that the cert doesn't work for
			// that purpose.
			results[i] = pkcs11.NewAttribute(attr.Type, uint(pkcs11.CKT_NSS_NOT_TRUSTED))
		} else if attr.Type == pkcs11.CKA_TRUST_CODE_SIGNING {
			// CKT_NSS_NOT_TRUSTED should be equivalent to
			// blacklisting the cert.
			// TODO: actually test that the cert doesn't work for
			// that purpose.
			results[i] = pkcs11.NewAttribute(attr.Type, uint(pkcs11.CKT_NSS_NOT_TRUSTED))
		} else if attr.Type == pkcs11.CKA_TRUST_EMAIL_PROTECTION {
			// CKT_NSS_NOT_TRUSTED should be equivalent to
			// blacklisting the cert.
			// TODO: actually test that the cert doesn't work for
			// that purpose.
			results[i] = pkcs11.NewAttribute(attr.Type, uint(pkcs11.CKT_NSS_NOT_TRUSTED))
		} else if attr.Type == pkcs11.CKA_TRUST_STEP_UP_APPROVED {
			// According to "certutil --help", "make step-up cert"
			// is the description of the "g" trust attribute.
			// According to the NSS "CERT_DecodeTrustString"
			// function, the "g" trust attribute corresponds to the
			// "CERTDB_GOVT_APPROVED_CA" flag.  The #define for
			// "CERTDB_GOVT_APPROVED_CA" includes the comment "can
			// do strong crypto in export ver".  So, I infer that
			// "step-up" refers to some kind of governmental
			// regulatory approval involving crypto export
			// controls.  According to "certdata.txt" in Mozilla's
			// Mercurial repo, all of the CKBI CA's have this
			// attribute set to false.
			results[i] = pkcs11.NewAttribute(attr.Type, false)
		} else if attr.Type == pkcs11.CKA_CERT_SHA1_HASH {
			// Yes, NSS is a pile of fail and uses SHA1 to identify
			// certificates.  They should probably fix this in the
			// future.
			sha1Array := sha1.Sum(cert.Raw)

			results[i] = pkcs11.NewAttribute(attr.Type, sha1Array[:])
		} else {
			results[i] = pkcs11.NewAttribute(attr.Type, nil)

			hasUnknownAttr = true
			unknownAttrs = append(unknownAttrs, attr.Type)
		}
	}

	if hasUnknownAttr {
		// We don't return CKR_ATTRIBUTE_TYPE_INVALID because that
		// would result in the application attempting to use the
		// results.
		log.Printf("GetAttributeValue requested unknown attribute types %v\n", unknownAttrs)
		return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	return results, nil
}

func (s *session) getCKBIDataToCrossSign(oh pkcs11.ObjectHandle) ([]byte, uint, error) {
	issuerRequest := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, []byte{}),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, []byte{}),
	}
	issuerResponse, err := s.backend.ckbiBackend.GetAttributeValue(s.ckbiSessionHandle, oh, issuerRequest)
	if err != nil {
		log.Printf("Error getting issuer and serial number to cross-sign: %s", err)
		return []byte{}, 0, err
	}

	// issuerResponse is a template that we can use to find the other object.

	err = s.backend.ckbiBackend.FindObjectsInit(s.ckbiSessionHandle, issuerResponse)
	if err != nil {
		return []byte{}, 0, err
	}

	objects, _, err := s.backend.ckbiBackend.FindObjects(s.ckbiSessionHandle, 2)
	if err != nil {
		return []byte{}, 0, err
	}

	err = s.backend.ckbiBackend.FindObjectsFinal(s.ckbiSessionHandle)
	if err != nil {
		return []byte{}, 0, err
	}

	valueRequest := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte{}),
	}

	trustRequest := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TRUST_SERVER_AUTH, 0),
	}

	valueResponse := []*pkcs11.Attribute{}
	trustResponse := []*pkcs11.Attribute{}

	valueSuccess := false
	trustSuccess := false

	for _, resultObject := range objects {
		if !valueSuccess {
			valueResponse, err = s.backend.ckbiBackend.GetAttributeValue(s.ckbiSessionHandle, resultObject, valueRequest)
			if err == pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID) {
				// Wrong class, not a problem
			} else if err != nil {
				log.Printf("Error getting value to cross-sign: %s", err)
				return []byte{}, 0, err
			} else {
				valueSuccess = true
			}
		}

		if !trustSuccess {
			trustResponse, err = s.backend.ckbiBackend.GetAttributeValue(s.ckbiSessionHandle, resultObject, trustRequest)
			if err == pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID) {
				// Wrong class, not a problem
			} else if err != nil {
				log.Printf("Error getting trust to cross-sign: %s", err)
				return []byte{}, 0, err
			} else {
				trustSuccess = true
			}
		}
	}

	if !valueSuccess {
		log.Printf("Missing value to cross-sign")
	}

	if !trustSuccess {
		log.Printf("Missing trust to cross-sign")
	}

	if !valueSuccess || !trustSuccess {
		return []byte{}, 0, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	trustResult, err := pkcs11mod.BytesToULong(trustResponse[0].Value)
	if err != nil {
		log.Printf("Invalid trust to cross-sign")
		return []byte{}, 0, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	return valueResponse[0].Value, trustResult, nil
}

func (b *BackendNamecoin) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	b.sessionMutex.RLock()
	s, sessionExists := b.sessions[sh]
	b.sessionMutex.RUnlock()

	if !sessionExists {
		log.Printf("FindObjectsInit: CKR_SESSION_HANDLE_INVALID\n")
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	// Handle CKBI proxying
	if s.slotID != b.slotPositive {
		if s.isRestrictSlot {
			for i, attr := range temp {
				if attr.Type == pkcs11.CKA_VALUE {
					log.Println("Unimplemented: Restrict FindObjectsInit CKA_VALUE")
				}

				if attr.Type == pkcs11.CKA_ISSUER {
					var dn1 pkix.RDNSequence
					if rest, err := asn1.Unmarshal(attr.Value, &dn1); err != nil {
						log.Printf("Error unmarshaling X.509 issuer: %v\n", err)
						continue
					} else if len(rest) != 0 {
						log.Printf("Error: trailing data after X.509 issuer\n")
						continue
					}

					var dn2 pkix.Name
					dn2.FillFromRDNSequence(&dn1)

					if dn2.SerialNumber == "Namecoin TLS Certificate" && strings.HasSuffix(dn2.CommonName, "TLD Exclusion CA") {
						if temp[i+1].Type == pkcs11.CKA_SERIAL_NUMBER {
							originalIssuer, originalSerial := b.originalIssuerAndSerialFromNewSerial(temp[i+1].Value)

							*temp[i] = *pkcs11.NewAttribute(attr.Type, originalIssuer)
							*temp[i+1] = *pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, originalSerial)
						} else {
							log.Println("Unable to find serial number to substitute original")
						}
					}
				}

				if attr.Type == pkcs11.CKA_SERIAL_NUMBER {
					// Technically someone might search by
					// serial number without issuer (which
					// would be a problem), but it's
					// unlikely, so don't log a warning.
					//log.Println("Unimplemented: Restrict FindObjectsInit CKA_SERIAL_NUMBER")
				}

				if attr.Type == pkcs11.CKA_TRUST_SERVER_AUTH {
					log.Println("Unimplemented: Restrict FindObjectsInit CKA_TRUST_SERVER_AUTH")
				}

				if attr.Type == pkcs11.CKA_CERT_SHA1_HASH {
					log.Println("Unimplemented: Restrict FindObjectsInit CKA_CERT_SHA1_HASH")
				}
			}
		}

		return b.ckbiBackend.FindObjectsInit(s.ckbiSessionHandle, temp)
	}

	var attrTypes []uint
	recognizedTemplate := false
	foundName := false
	var domain string

	for _, attr := range temp {
		attrTypes = append(attrTypes, attr.Type)

		if attr.Type == pkcs11.CKA_ISSUER || attr.Type == pkcs11.CKA_SUBJECT {
			recognizedTemplate = true

			var dn1 pkix.RDNSequence
			if rest, err := asn1.Unmarshal(attr.Value, &dn1); err != nil {
				log.Printf("Error unmarshaling X.509 issuer or subject: %v\n", err)
				continue
			} else if len(rest) != 0 {
				log.Printf("Error: trailing data after X.509 issuer or subject\n")
				continue
			}

			var dn2 pkix.Name
			dn2.FillFromRDNSequence(&dn1)

			if dn2.SerialNumber == "Namecoin TLS Certificate" {
				domain = dn2.CommonName

				log.Printf("Issuer/Subject CommonName: %s\n", domain)

				foundName = true
			}
		} else if attr.Type == pkcs11.CKA_VALUE {
			// Looking up certs by value seems to happen in Firefox
			// on GNU/Linux when CKBI impersonation is enabled.

			cert, err := x509.ParseCertificate(attr.Value)
			if err != nil {
				continue
			}

			recognizedTemplate = true

			if cert.Subject.SerialNumber == "Namecoin TLS Certificate" {
				domain = cert.Subject.CommonName

				log.Printf("Value Subject CommonName: %s\n", domain)

				foundName = true
			} else if cert.Issuer.SerialNumber == "Namecoin TLS Certificate" {
				domain = cert.Issuer.CommonName

				log.Printf("Value Issuer CommonName: %s\n", domain)

				foundName = true
			}
		}
	}

	if foundName {
		// We found the name, so we can start the certificate lookup
		// procedure.

		s.certs = make(chan *certObject)
		s.domain = domain
		s.template = temp

		go s.lookupCerts(s.certs)
	} else if recognizedTemplate {
		// The cert being queried isn't a Namecoin certificate, so
		// return an empty list.
		s.certs = make(chan *certObject)
		s.template = temp

		go s.lookupEmptyList(s.certs)
	} else if len(attrTypes) == 0 {
		// The application is requesting a complete list of all
		// Namecoin certificates.  We don't support this use case, so
		// we'll pretend that no certificates were found.  This variant
		// seems to show up from pkcs11-dump.
		s.certs = make(chan *certObject)
		s.template = temp

		go s.lookupEmptyList(s.certs)
	} else if len(attrTypes) == 1 && attrTypes[0] == pkcs11.CKA_CLASS {
		// Ditto.  This variant seems to show up from Chromium on
		// GNU/Linux during initial boot.
		s.certs = make(chan *certObject)
		s.template = temp

		go s.lookupEmptyList(s.certs)
	} else if len(attrTypes) == 2 && attrTypes[0] == pkcs11.CKA_ID && attrTypes[1] == pkcs11.CKA_CLASS {
		// Ditto.  This variant seems to show up from Chromium on
		// GNU/Linux during certificate validation.

		s.certs = make(chan *certObject)
		s.template = temp

		go s.lookupEmptyList(s.certs)
	} else if len(attrTypes) == 2 && attrTypes[0] == pkcs11.CKA_VALUE && attrTypes[1] == pkcs11.CKA_CLASS {
		// This variant seems to legitimately show up from Firefox on
		// GNU/Linux when CKBI impersonation is enabled, but in such
		// cases CKA_CLASS is CKO_CERTIFICATE, and the CKA_VALUE
		// recognition will successfully parse an x509.Certificate,
		// meaning we won't end up here.  So, if we've landed here,
		// that means either CKA_CLASS is something unexpected, or the
		// CKA_VALUE is an invalid certificate.

		log.Printf("FindObjectsInit template includes CKA_VALUE and unknown CKA_CLASS=%v\n", temp[1].Value)

		s.certs = make(chan *certObject)
		s.template = temp

		go s.lookupEmptyList(s.certs)
	} else {
		log.Printf("Unknown FindObjectsInit template types: %v\n", attrTypes)
		s.certs = make(chan *certObject)
		s.template = temp

		go s.lookupEmptyList(s.certs)
	}

	return nil
}

func (b *BackendNamecoin) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	b.sessionMutex.RLock()
	s, sessionExists := b.sessions[sh]
	b.sessionMutex.RUnlock()

	if !sessionExists {
		log.Printf("FindObjects: CKR_SESSION_HANDLE_INVALID\n")
		return []pkcs11.ObjectHandle{}, false, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	// Handle CKBI proxying
	if s.slotID != b.slotPositive {
		return b.ckbiBackend.FindObjects(s.ckbiSessionHandle, max)
	}

	result := []pkcs11.ObjectHandle{}

	var co *certObject
	var ok bool

	for len(result) < max {
		co, ok = <- s.certs
		if !ok {
			break
		}

		if !certMatchesTemplate(co, s.template) {
			continue
		}

		s.objects = append(s.objects, co)
		result = append(result, pkcs11.ObjectHandle(len(s.objects)))
	}

	return result, false, nil
}

func (b *BackendNamecoin) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	// TODO: clean up any data created during the FindObjects operation

	b.sessionMutex.RLock()
	s, sessionExists := b.sessions[sh]
	b.sessionMutex.RUnlock()

	if !sessionExists {
		log.Printf("FindObjectsFinal: CKR_SESSION_HANDLE_INVALID\n")
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	// Handle CKBI proxying
	if s.slotID != b.slotPositive {
		if s.isRestrictSlot {
		}

		return b.ckbiBackend.FindObjectsFinal(s.ckbiSessionHandle)
	}

	return nil
}

func (s *session) lookupCerts(dest chan *certObject) {
	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}

	postArgs := url.Values{}
	postArgs.Set("domain", s.domain)

	response, err := netClient.PostForm("http://127.0.0.1:8080/lookup", postArgs)
	if err != nil {
		close(dest)
		log.Printf("Error POSTing to cert API: %s\n", err)
		return
	}

	buf, err := ioutil.ReadAll(response.Body)
	if err != nil {
		close(dest)
		log.Printf("Error reading response from cert API: %s\n", err)
		return
	}

	err = response.Body.Close()
	if err != nil {
		close(dest)
		log.Printf("Error closing response from cert API: %s\n", err)
		return
	}

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

		dest <- &certObject{
			cert: cert,
			class: pkcs11.CKO_CERTIFICATE,
		}

		dest <- &certObject{
			cert: cert,
			class: pkcs11.CKO_NSS_TRUST,
		}
	}

	s.lookupEmptyList(dest)
}

func (s *session) lookupEmptyList(dest chan *certObject) {
	if s.backend.enableImpersonateCKBI {
		dest <- &certObject{
			cert: &x509.Certificate{},
			class: pkcs11.CKO_NSS_BUILTIN_ROOT_LIST,
		}
	}

	if s.backend.enableRestrictCKBI {
		s.backend.obtainRestrictCA()

		dest <- &certObject{
			cert: s.backend.ckbiRestrictCert,
			class: pkcs11.CKO_CERTIFICATE,
		}
	}

	close(dest)
}

func (b *BackendNamecoin) obtainRestrictCA() {
	// If we already have the restriction CA, then we don't need to get it
	// again.
	if b.ckbiRestrictCertPEM != "" && b.ckbiRestrictPrivPEM != "" {
		return
	}

	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}

	postArgs := url.Values{}

	response, err := netClient.PostForm("http://127.0.0.1:8080/get-new-negative-ca", postArgs)
	if err != nil {
		log.Printf("Error POSTing to get-new-negative-ca API: %s\n", err)
		return
	}

	buf, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf("Error reading response from get-new-negative-ca API: %s\n", err)
		return
	}

	err = response.Body.Close()
	if err != nil {
		log.Printf("Error closing response from get-new-negative-ca API: %s\n", err)
		return
	}

	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			b.ckbiRestrictCert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}

			restrictCertPem := pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE",
				Bytes: block.Bytes,
			})
			b.ckbiRestrictCertPEM = string(restrictCertPem)
		}

		if block.Type == "EC PRIVATE KEY" {
			restrictPrivPem := pem.EncodeToMemory(&pem.Block{
				Type: "EC PRIVATE KEY",
				Bytes: block.Bytes,
			})
			b.ckbiRestrictPrivPEM = string(restrictPrivPem)
		}
	}
}

func (b *BackendNamecoin) crossSignCKBI(in []byte) []byte {
	inPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE",
		Bytes: in,
	})
	inPEMString := string(inPEM)

	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}

	postArgs := url.Values{}
	postArgs.Set("to-sign", inPEMString)
	postArgs.Set("signer-cert", b.ckbiRestrictCertPEM)
	postArgs.Set("signer-key", b.ckbiRestrictPrivPEM)

	response, err := netClient.PostForm("http://127.0.0.1:8080/cross-sign-ca", postArgs)
	if err != nil {
		log.Printf("Error POSTing to cert API: %s\n", err)
		return []byte{}
	}

	buf, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf("Error reading response from cert API: %s\n", err)
		return []byte{}
	}

	err = response.Body.Close()
	if err != nil {
		log.Printf("Error closing response from cert API: %s\n", err)
		return []byte{}
	}

	var block *pem.Block
	block, _ = pem.Decode(buf)
	if block == nil {
		return []byte{}
	}

	if block.Type != "CERTIFICATE" {
		return []byte{}
	}

	return block.Bytes
}

func (b *BackendNamecoin) originalIssuerAndSerialFromNewSerial(serial []byte) ([]byte, []byte) {
	// Yes, we pass a pointer to a pointer to Unmarshal, see https://stackoverflow.com/questions/53139020/why-is-unmarshalling-of-a-der-asn-1-large-integer-limited-to-sequence-in-golang
	var serialBig *big.Int
	_, err := asn1.Unmarshal(serial, &serialBig)
	if err != nil {
		log.Printf("Error parsing new serial number: %s", err)
	}

	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}

	postArgs := url.Values{}
	postArgs.Set("serial", serialBig.String())

	response, err := netClient.PostForm("http://127.0.0.1:8080/original-from-serial", postArgs)
	if err != nil {
		log.Printf("Error POSTing to cert API: %s\n", err)
		return []byte{}, []byte{}
	}

	buf, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf("Error reading response from cert API: %s\n", err)
		return []byte{}, []byte{}
	}

	err = response.Body.Close()
	if err != nil {
		log.Printf("Error closing response from cert API: %s\n", err)
		return []byte{}, []byte{}
	}

	var block *pem.Block
	block, _ = pem.Decode(buf)
	if block == nil {
		return []byte{}, []byte{}
	}

	if block.Type != "CERTIFICATE" {
		return []byte{}, []byte{}
	}

	originalCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return []byte{}, []byte{}
	}

	originalSerialNumber, err := asn1.Marshal(originalCert.SerialNumber)
	if err != nil {
		log.Printf("Error marshaling SerialNumber from original cert")
		return []byte{}, []byte{}
	}

	return originalCert.RawIssuer, originalSerialNumber
}

func certMatchesTemplate(co *certObject, template []*pkcs11.Attribute) bool {
	cert := co.cert
	if cert == nil {
		log.Printf("nil cert couldn't be matched against template\n")
		return false
	}

	for _, attr := range template {
		if attr.Type == pkcs11.CKA_CLASS {
			templateClass, err := pkcs11mod.BytesToULong(attr.Value)
			if err != nil {
				log.Printf("Template contains invalid CKA_CLASS %v\n", attr.Value)
				return false
			}

			// The valid values expected by NSS seem to be:
			// CKO_CERTIFICATE and CKO_NSS_TRUST
			//
			// CKO_CERTIFICATE stores the certificate's contents,
			// as well as CKA_NSS_MOZILLA_CA_POLICY which is
			// relevant to HPKP enforcement.
			//
			// CKO_NSS_TRUST stores most of the certificate's trust
			// attributes.
			if templateClass == co.class {
				continue
			}

			if templateClass != pkcs11.CKO_CERTIFICATE && templateClass != pkcs11.CKO_NSS_TRUST {
				log.Printf("Template contains unknown CKA_CLASS %v\n", templateClass)
			}

			return false
		} else if attr.Type == pkcs11.CKA_TOKEN {
			// Only accept token objects
			templateIsToken, err := pkcs11mod.BytesToBool(attr.Value)
			if err != nil {
				log.Printf("Template contains invalid CKA_TOKEN %v\n", attr.Value)
				return false
			}

			if !templateIsToken {
				return false
			}
		} else if attr.Type == pkcs11.CKA_VALUE {
			templateValue := attr.Value
			certValue := cert.Raw

			if !bytes.Equal(certValue, templateValue) {
				return false
			}
		} else if attr.Type == pkcs11.CKA_ISSUER {
			templateIssuer := attr.Value
			certIssuer := cert.RawIssuer

			if !bytes.Equal(certIssuer, templateIssuer) {
				return false
			}
		} else if attr.Type == pkcs11.CKA_SERIAL_NUMBER {
			templateSerialNumber := attr.Value
			certSerialNumber, err := asn1.Marshal(cert.SerialNumber)
			if err != nil {
				log.Printf("Error marshaling SerialNumber from dehydrated cert")
				return false
			}

			if !bytes.Equal(certSerialNumber, templateSerialNumber) {
				return false
			}
		} else if attr.Type == pkcs11.CKA_SUBJECT {
			templateSubject := attr.Value
			certSubject := cert.RawSubject

			if !bytes.Equal(certSubject, templateSubject) {
				return false
			}
		} else if attr.Type == pkcs11.CKA_ID {
			if !bytes.Equal([]byte("0"), attr.Value) {
				return false
			}
		} else {
			log.Printf("Template contains unknown attribute %v\n", attr.Type)
			return false
		}
	}

	return true
}
