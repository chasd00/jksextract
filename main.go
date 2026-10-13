// Command jksextract extracts the public certificate (and certificate chain)
// and the private key for a single alias from a Java KeyStore (JKS) file and
// writes them out as PEM files that OpenSSL, nginx, Apache, Go, Node.js and
// most other tooling understand.
//
// The keystore password and the alias are prompted for interactively so that
// secrets never appear in shell history or process listings.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

type options struct {
	keystorePath string
	alias        string
	outDir       string
	certFile     string
	keyFile      string
	chain        bool
	force        bool
	listOnly     bool
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(1)
	}
}

func run(args []string, stdin *os.File, stdout, stderr io.Writer) error {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(opts.keystorePath)
	if err != nil {
		return fmt.Errorf("read keystore: %w", err)
	}
	if err := checkFormat(data); err != nil {
		return err
	}

	p := newPrompter(stdin, stderr)

	storePass, err := p.password(fmt.Sprintf("Keystore password for %s: ", filepath.Base(opts.keystorePath)))
	if err != nil {
		return err
	}
	defer zero(storePass)

	ks, err := loadKeystore(data, storePass)
	if err != nil {
		return err
	}

	entries := listEntries(ks)
	if len(entries) == 0 {
		return errors.New("keystore contains no entries")
	}

	if opts.listOnly {
		printEntries(stdout, entries)
		return nil
	}

	alias := opts.alias
	if alias == "" {
		fmt.Fprintln(stderr)
		printEntries(stderr, entries)
		def := defaultAlias(entries)
		label := "Certificate alias"
		if def != "" {
			label += fmt.Sprintf(" [%s]", def)
		}
		alias, err = p.line(label + ": ")
		if err != nil {
			return err
		}
		if alias == "" {
			alias = def
		}
		if alias == "" {
			return errors.New("no alias given")
		}
	}

	res, err := extract(ks, alias, storePass, func() ([]byte, error) {
		return p.password(fmt.Sprintf("Key password for %q (differs from keystore password): ", alias))
	})
	if err != nil {
		return err
	}
	defer zero(res.KeyPEM)

	return writeOutputs(opts, res, stdout)
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	var opts options
	fs := flag.NewFlagSet("jksextract", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.alias, "alias", "", "alias to extract (prompted for if omitted)")
	fs.StringVar(&opts.outDir, "out", ".", "directory to write the output files to")
	fs.StringVar(&opts.certFile, "cert-file", "", "certificate output file name (default <alias>.crt)")
	fs.StringVar(&opts.keyFile, "key-file", "", "private key output file name (default <alias>.key)")
	fs.BoolVar(&opts.chain, "chain", false, "also write the full certificate chain to <alias>-chain.crt")
	fs.BoolVar(&opts.force, "force", false, "overwrite existing output files")
	fs.BoolVar(&opts.listOnly, "list", false, "list the aliases in the keystore and exit")
	showVersion := fs.Bool("version", false, "print version and exit")

	fs.Usage = func() {
		fmt.Fprintf(stderr, `jksextract %s
Extract a certificate and private key from a Java KeyStore (JKS) as PEM files.

Usage:
  jksextract [flags] <keystore.jks>

You will be prompted for the keystore password and, unless -alias is given,
for the alias to extract.

Flags:
`, version)
		fs.PrintDefaults()
	}

	// Allow flags after the keystore path as well as before it.
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return opts, err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	if *showVersion {
		fmt.Fprintf(stderr, "jksextract %s\n", version)
		os.Exit(0)
	}
	if len(positional) != 1 {
		fs.Usage()
		return opts, errors.New("exactly one keystore file must be given")
	}
	opts.keystorePath = positional[0]
	opts.alias = strings.TrimSpace(opts.alias)
	return opts, nil
}

func printEntries(w io.Writer, entries []entryInfo) {
	fmt.Fprintln(w, "Entries in keystore:")
	for _, e := range entries {
		kind := "certificate only"
		if e.HasKey {
			kind = "private key + certificate"
		}
		fmt.Fprintf(w, "  %-30s %s\n", e.Alias, kind)
	}
}

// defaultAlias returns the alias to suggest: the only private-key entry if
// there is exactly one, otherwise the only entry if there is exactly one.
func defaultAlias(entries []entryInfo) string {
	var keyAliases []string
	for _, e := range entries {
		if e.HasKey {
			keyAliases = append(keyAliases, e.Alias)
		}
	}
	if len(keyAliases) == 1 {
		return keyAliases[0]
	}
	if len(entries) == 1 {
		return entries[0].Alias
	}
	return ""
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
