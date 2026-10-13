package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func makeKeystore(t *testing.T, storePass, keyPass []byte) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	ks := keystore.New()
	cert := keystore.Certificate{Type: "X509", Content: der}
	if err := ks.SetPrivateKeyEntry("mykey", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       pkcs8,
		CertificateChain: []keystore.Certificate{cert},
	}, clone(keyPass)); err != nil {
		t.Fatal(err)
	}
	if err := ks.SetTrustedCertificateEntry("trusted", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(), Certificate: cert,
	}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, clone(storePass)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractSamePassword(t *testing.T) {
	pass := []byte("changeit")
	data := makeKeystore(t, pass, pass)
	if err := checkFormat(data); err != nil {
		t.Fatal(err)
	}
	ks, err := loadKeystore(data, pass)
	if err != nil {
		t.Fatal(err)
	}
	res, err := extract(ks, "MyKey", pass, func() ([]byte, error) {
		t.Fatal("key password should not be requested")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Leaf.Subject.CommonName != "test.example.com" {
		t.Errorf("unexpected subject %v", res.Leaf.Subject)
	}
	block, _ := pem.Decode(res.KeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("bad key PEM: %q", res.KeyPEM)
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatal(err)
	}
	if res.KeyType != "ECDSA P-256" {
		t.Errorf("KeyType = %q", res.KeyType)
	}
}

func TestExtractSeparateKeyPassword(t *testing.T) {
	data := makeKeystore(t, []byte("storepass"), []byte("keypass"))
	ks, err := loadKeystore(data, []byte("storepass"))
	if err != nil {
		t.Fatal(err)
	}
	asked := false
	res, err := extract(ks, "mykey", []byte("storepass"), func() ([]byte, error) {
		asked = true
		return []byte("keypass"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !asked || res.KeyPEM == nil {
		t.Fatal("expected key password prompt and a key")
	}

	_, err = extract(ks, "mykey", []byte("storepass"), func() ([]byte, error) {
		return []byte("wrong"), nil
	})
	if err == nil || !strings.Contains(err.Error(), "incorrect key password") {
		t.Fatalf("expected incorrect key password error, got %v", err)
	}
}

func TestWrongStorePassword(t *testing.T) {
	data := makeKeystore(t, []byte("changeit"), []byte("changeit"))
	if _, err := loadKeystore(data, []byte("nope")); err == nil ||
		!strings.Contains(err.Error(), "incorrect keystore password") {
		t.Fatalf("expected password error, got %v", err)
	}
}

func TestTrustedCertificateEntry(t *testing.T) {
	pass := []byte("changeit")
	ks, err := loadKeystore(makeKeystore(t, pass, pass), pass)
	if err != nil {
		t.Fatal(err)
	}
	res, err := extract(ks, "trusted", pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.KeyPEM != nil {
		t.Error("trusted entry should have no key")
	}
}

func TestUnknownAlias(t *testing.T) {
	pass := []byte("changeit")
	ks, _ := loadKeystore(makeKeystore(t, pass, pass), pass)
	if _, err := extract(ks, "missing", pass, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestCheckFormat(t *testing.T) {
	cases := map[string][]byte{
		"PKCS#12": {0x30, 0x82, 0x01, 0x00},
		"JCEKS":   {0xCE, 0xCE, 0xCE, 0xCE},
		"JKS":     {0xFE, 0xED, 0xFE, 0xED},
	}
	for name, data := range cases {
		err := checkFormat(data)
		if (name == "JKS") != (err == nil) {
			t.Errorf("%s: unexpected result %v", name, err)
		}
	}
}

func TestWriteOutputs(t *testing.T) {
	pass := []byte("changeit")
	ks, _ := loadKeystore(makeKeystore(t, pass, pass), pass)
	res, err := extract(ks, "mykey", pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	opts := options{outDir: dir, chain: true}
	var out bytes.Buffer
	if err := writeOutputs(opts, res, &out); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"mykey.crt", "mykey.key", "mykey-chain.crt"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	if err := writeOutputs(opts, res, &out); err == nil {
		t.Error("expected refusal to overwrite without -force")
	}
	opts.force = true
	if err := writeOutputs(opts, res, &out); err != nil {
		t.Errorf("force overwrite failed: %v", err)
	}
}

func TestToJavaPassword(t *testing.T) {
	got, err := toJavaPassword([]byte("pässword"))
	if err != nil || !bytes.Equal(got, []byte{'p', 0xE4, 's', 's', 'w', 'o', 'r', 'd'}) {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := toJavaPassword([]byte("密码")); err == nil {
		t.Fatal("expected error for non-Latin-1 password")
	}
}

func TestSafeFileName(t *testing.T) {
	for in, want := range map[string]string{
		"server":         "server",
		"my cert/1":      "my_cert_1",
		"..":             "entry",
		"c:\\x":          "c__x",
		"www.example.io": "www.example.io",
	} {
		if got := safeFileName(in); got != want {
			t.Errorf("safeFileName(%q) = %q, want %q", in, got, want)
		}
	}
}
