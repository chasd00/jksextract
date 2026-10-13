package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func writeOutputs(opts options, res *result, stdout io.Writer) error {
	base := safeFileName(res.Alias)
	certName := opts.certFile
	if certName == "" {
		certName = base + ".crt"
	}
	keyName := opts.keyFile
	if keyName == "" {
		keyName = base + ".key"
	}
	certPath := filepath.Join(opts.outDir, certName)
	keyPath := filepath.Join(opts.outDir, keyName)
	chainPath := filepath.Join(opts.outDir, base+"-chain.crt")

	type out struct {
		path string
		data []byte
		mode fs.FileMode
	}
	outputs := []out{{certPath, res.CertPEM, 0o644}}
	if opts.chain {
		outputs = append(outputs, out{chainPath, res.ChainPEM, 0o644})
	}
	if res.KeyPEM != nil {
		outputs = append(outputs, out{keyPath, res.KeyPEM, 0o600})
	}

	if !opts.force {
		for _, o := range outputs {
			if _, err := os.Stat(o.path); err == nil {
				return fmt.Errorf("%s already exists (use -force to overwrite)", o.path)
			}
		}
	}
	if err := os.MkdirAll(opts.outDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	for _, o := range outputs {
		if err := writeFile(o.path, o.data, o.mode); err != nil {
			return err
		}
	}

	leaf := res.Leaf
	fp := sha256.Sum256(leaf.Raw)
	fmt.Fprintf(stdout, "\nAlias:       %s\n", res.Alias)
	fmt.Fprintf(stdout, "Subject:     %s\n", leaf.Subject)
	fmt.Fprintf(stdout, "Issuer:      %s\n", leaf.Issuer)
	fmt.Fprintf(stdout, "Valid:       %s to %s", leaf.NotBefore.UTC().Format(time.DateOnly), leaf.NotAfter.UTC().Format(time.DateOnly))
	if time.Now().After(leaf.NotAfter) {
		fmt.Fprint(stdout, "  (EXPIRED)")
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "SHA-256:     %s\n", colonHex(fp[:]))
	if res.KeyType != "" {
		fmt.Fprintf(stdout, "Key:         %s (matches certificate)\n", res.KeyType)
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "Wrote certificate:  %s\n", certPath)
	if opts.chain {
		fmt.Fprintf(stdout, "Wrote chain (%d):    %s\n", len(res.Chain), chainPath)
	}
	if res.KeyPEM != nil {
		fmt.Fprintf(stdout, "Wrote private key:  %s  (unencrypted - keep it safe)\n", keyPath)
	} else {
		fmt.Fprintln(stdout, "Note: this alias is a trusted-certificate entry; it has no private key.")
	}
	return nil
}

// writeFile writes data to path with the given permissions, applying the
// permissions even when overwriting an existing file.
func writeFile(path string, data []byte, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// Tighten permissions on an existing file too. Best-effort: Windows only
	// honours the read-only bit, so key files there inherit the folder's ACL.
	_ = f.Chmod(mode)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// safeFileName turns an alias into something usable as a file name on
// macOS, Linux and Windows.
func safeFileName(alias string) string {
	var b strings.Builder
	for _, r := range alias {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	s := strings.Trim(b.String(), ".")
	if s == "" {
		s = "entry"
	}
	return s
}

func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}
