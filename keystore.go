package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

const (
	magicJKS   = 0xFEEDFEED
	magicJCEKS = 0xCECECECE
)

// checkFormat looks at the file's magic number and returns a helpful error for
// keystore formats this tool does not read.
func checkFormat(data []byte) error {
	if len(data) < 4 {
		return errors.New("file is too small to be a keystore")
	}
	switch binary.BigEndian.Uint32(data[:4]) {
	case magicJKS:
		return nil
	case magicJCEKS:
		return errors.New("this is a JCEKS keystore, which is not supported; convert it to JKS first:\n" +
			"  keytool -importkeystore -srckeystore in.jceks -srcstoretype JCEKS -destkeystore out.jks -deststoretype JKS")
	}
	if data[0] == 0x30 { // ASN.1 SEQUENCE: almost certainly PKCS#12
		return errors.New("this looks like a PKCS#12 keystore (the default format for keytool since Java 9), not JKS.\n" +
			"OpenSSL can read it directly:\n" +
			"  openssl pkcs12 -in keystore.p12 -nokeys -out cert.crt\n" +
			"  openssl pkcs12 -in keystore.p12 -nocerts -nodes -out key.key\n" +
			"or convert it to JKS first:\n" +
			"  keytool -importkeystore -srckeystore keystore.p12 -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype JKS")
	}
	return errors.New("not a Java KeyStore (JKS) file")
}

func loadKeystore(data, password []byte) (keystore.KeyStore, error) {
	ks := keystore.New()
	// The library zeroes the password it is given, so hand it a copy.
	if err := ks.Load(bytes.NewReader(data), clone(password)); err != nil {
		if strings.Contains(err.Error(), "invalid digest") {
			return ks, errors.New("incorrect keystore password (or the file is corrupted)")
		}
		return ks, fmt.Errorf("load keystore: %w", err)
	}
	return ks, nil
}

type entryInfo struct {
	Alias  string
	HasKey bool
}

func listEntries(ks keystore.KeyStore) []entryInfo {
	aliases := ks.Aliases()
	sort.Strings(aliases)
	out := make([]entryInfo, 0, len(aliases))
	for _, a := range aliases {
		out = append(out, entryInfo{Alias: a, HasKey: ks.IsPrivateKeyEntry(a)})
	}
	return out
}

// result holds everything extracted for one alias, already PEM encoded.
type result struct {
	Alias    string
	Leaf     *x509.Certificate
	Chain    []*x509.Certificate
	CertPEM  []byte // leaf certificate only
	ChainPEM []byte // leaf followed by the rest of the chain
	KeyPEM   []byte // PKCS#8 "PRIVATE KEY"; nil for certificate-only entries
	KeyType  string
}

// extract pulls the certificate(s) and private key for alias out of ks. The
// private key is first decrypted with storePass; if that fails, askKeyPass is
// called to obtain a separate key password.
func extract(ks keystore.KeyStore, alias string, storePass []byte, askKeyPass func() ([]byte, error)) (*result, error) {
	// JKS aliases are case-insensitive and stored lower-case.
	lookup := strings.ToLower(alias)

	switch {
	case ks.IsPrivateKeyEntry(lookup):
		entry, err := ks.GetPrivateKeyEntry(lookup, clone(storePass))
		if err != nil {
			keyPass, perr := askKeyPass()
			if perr != nil {
				return nil, perr
			}
			defer zero(keyPass)
			entry, err = ks.GetPrivateKeyEntry(lookup, clone(keyPass))
			if err != nil {
				return nil, errors.New("incorrect key password")
			}
		}
		defer zero(entry.PrivateKey)
		return buildResult(lookup, entry.CertificateChain, entry.PrivateKey)

	case ks.IsTrustedCertificateEntry(lookup):
		entry, err := ks.GetTrustedCertificateEntry(lookup)
		if err != nil {
			return nil, err
		}
		return buildResult(lookup, []keystore.Certificate{entry.Certificate}, nil)
	}
	return nil, fmt.Errorf("alias %q not found in keystore", alias)
}

func buildResult(alias string, chain []keystore.Certificate, pkcs8 []byte) (*result, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("alias %q has no certificate", alias)
	}
	res := &result{Alias: alias}
	var certBuf, chainBuf bytes.Buffer
	for i, c := range chain {
		if c.Type != "" && c.Type != "X509" && c.Type != "X.509" {
			return nil, fmt.Errorf("unsupported certificate type %q", c.Type)
		}
		cert, err := x509.ParseCertificate(c.Content)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %d: %w", i, err)
		}
		block := &pem.Block{Type: "CERTIFICATE", Bytes: c.Content}
		if i == 0 {
			res.Leaf = cert
			_ = pem.Encode(&certBuf, block)
		}
		res.Chain = append(res.Chain, cert)
		_ = pem.Encode(&chainBuf, block)
	}
	res.CertPEM = certBuf.Bytes()
	res.ChainPEM = chainBuf.Bytes()

	if pkcs8 != nil {
		key, err := x509.ParsePKCS8PrivateKey(pkcs8)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		if err := checkKeyMatchesCert(key, res.Leaf); err != nil {
			return nil, err
		}
		res.KeyType = describeKey(key)
		res.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	}
	return res, nil
}

func checkKeyMatchesCert(key any, cert *x509.Certificate) error {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil // can't check; don't block extraction
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := signer.Public().(equaler)
	if ok && !pub.Equal(cert.PublicKey) {
		return errors.New("private key does not match the certificate's public key")
	}
	return nil
}

func describeKey(key any) string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return fmt.Sprintf("RSA %d-bit", k.N.BitLen())
	case *ecdsa.PrivateKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PrivateKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", key)
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }
