# jksextract

A small command-line tool, shipped as a single self-contained binary, that pulls the **public certificate** and **private key** for one alias out of a Java KeyStore (`.jks`) and writes them as standard PEM files, ready for nginx, Apache, HAProxy, Node.js, Go, OpenSSL, Kubernetes secrets and anything else that doesn't speak JKS.

It prompts for the keystore password and the alias, so secrets never land in your shell history or in a process listing.

```text
$ jksextract server.jks
Keystore password for server.jks:

Entries in keystore:
  myca                           private key + certificate
  server                         private key + certificate
  trusted-ca                     certificate only
Certificate alias: server

Alias:       server
Subject:     CN=server.example.com
Issuer:      CN=Test CA
Valid:       2026-10-13 to 2027-01-11
SHA-256:     E7:19:7E:4E:B3:E5:E9:83:97:42:AB:48:2F:B0:9A:D9:9C:00:C0:3A:DC:6A:CC:4F:0D:2E:2C:10:1C:5E:9B:D9
Key:         RSA 2048-bit (matches certificate)

Wrote certificate:  server.crt
Wrote private key:  server.key  (unencrypted - keep it safe)
```

## Why

The usual way to do this needs two tools and two steps (`keytool -importkeystore` to PKCS#12, then `openssl pkcs12`), a JDK on the machine, and the passwords typed on the command line. `jksextract` is a single static binary for macOS, Windows and Linux that does it in one step.

## Features

- Reads JKS keystores (the `0xFEEDFEED` format used by `keytool` before Java 9 and still common in the wild)
- Prompts for the keystore password without echoing it, then lists the aliases and prompts for the one to extract
- Handles a **separate key password**: if the key isn't protected by the keystore password, you're asked for the key password
- Writes the private key as unencrypted PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`): RSA, EC and other key types
- Optionally writes the **full certificate chain** (`-chain`)
- Extracts trusted-certificate entries too (certificate only)
- Checks that the private key actually matches the certificate before writing anything
- Creates the key file with `0600` permissions on macOS and Linux, and refuses to overwrite existing files unless you pass `-force`
- Gives a clear message, with the commands to use, when handed a PKCS#12 or JCEKS keystore instead

## Installation

### Download a prebuilt binary

Prebuilt binaries are in the [`bin/`](bin/) folder of this repository:

| Platform                      | File                                 |
| ----------------------------- | ------------------------------------ |
| macOS, Apple silicon (M1–M4)  | `bin/jksextract-darwin-arm64`        |
| macOS, Intel                  | `bin/jksextract-darwin-amd64`        |
| Windows, x64                  | `bin/jksextract-windows-amd64.exe`   |
| Windows, ARM                  | `bin/jksextract-windows-arm64.exe`   |
| Linux, x64                    | `bin/jksextract-linux-amd64`         |
| Linux, ARM64                  | `bin/jksextract-linux-arm64`         |

**macOS:** the binaries aren't signed or notarized, so macOS blocks them if they were downloaded through a browser. After downloading:

```sh
chmod +x jksextract-darwin-arm64
xattr -d com.apple.quarantine jksextract-darwin-arm64   # clear Gatekeeper's "downloaded" flag
sudo mv jksextract-darwin-arm64 /usr/local/bin/jksextract
```

**Windows:** rename the file to `jksextract.exe` and put it in a folder on your `PATH`. SmartScreen may warn about an unrecognised app the first time you run it; choose **More info → Run anyway**.

### Install with Go

With Go 1.23 or newer:

```sh
go install github.com/chasd00/jksextract@latest
```

This puts `jksextract` in `$(go env GOPATH)/bin`.

## Building from source

You need [Go 1.23 or newer](https://go.dev/dl/) and Git. No C compiler is needed; builds are fully static (`CGO_ENABLED=0`).

```sh
git clone https://github.com/chasd00/jksextract.git
cd jksextract
```

### macOS

Install Go with the installer from [go.dev/dl](https://go.dev/dl/) or with Homebrew:

```sh
brew install go
```

Then build:

```sh
make            # builds ./jksextract for this Mac
make test       # runs the unit tests
make all        # cross-compiles every target (macOS, Windows, Linux) into bin/
make universal  # builds bin/jksextract-darwin-universal (Apple silicon + Intel in one file)
```

`make` comes with the Xcode Command Line Tools (`xcode-select --install`). Without `make`, run Go directly:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o jksextract .
```

### Windows

Install Go with the MSI installer from [go.dev/dl](https://go.dev/dl/), or with winget:

```powershell
winget install GoLang.Go
```

Open a new PowerShell window so `go` is on your `PATH`, then build:

```powershell
.\build.ps1          # builds .\jksextract.exe for this PC
.\build.ps1 -All     # cross-compiles every target into bin\
go test ./...        # runs the unit tests
```

If PowerShell refuses to run the script because of the execution policy, allow it for the current window only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Or build without the script, from PowerShell or `cmd`:

```powershell
go build -trimpath -ldflags "-s -w" -o jksextract.exe .
```

### Cross-compiling

Go cross-compiles from any platform to any other. From a Mac, `make windows` builds the Windows `.exe` files; from Windows, `.\build.ps1 -All` builds the macOS binaries. To build one target by hand, set `GOOS` and `GOARCH`:

```sh
GOOS=windows GOARCH=amd64 go build -o jksextract.exe .    # macOS / Linux shell
```

```powershell
$env:GOOS="darwin"; $env:GOARCH="arm64"; go build -o jksextract-darwin-arm64 .   # PowerShell
```

The version printed by `jksextract -version` comes from `git describe`; set it explicitly with `make VERSION=1.2.0` or `.\build.ps1 -Version 1.2.0`.

## Usage

```text
jksextract [flags] <keystore.jks>

Flags:
  -alias string       alias to extract (prompted for if omitted)
  -out string         directory to write the output files to (default ".")
  -cert-file string   certificate output file name (default <alias>.crt)
  -key-file string    private key output file name (default <alias>.key)
  -chain              also write the full certificate chain to <alias>-chain.crt
  -force              overwrite existing output files
  -list               list the aliases in the keystore and exit
  -version            print version and exit
```

The keystore password is always prompted for. If you don't pass `-alias`, the tool lists the entries and prompts for one; when the keystore holds exactly one private key, that alias is offered as the default and you can just press Enter.

### Examples

List what's in a keystore:

```sh
jksextract -list keystore.jks
```

Extract the `tomcat` entry, including its chain, into `./certs`:

```sh
jksextract -alias tomcat -chain -out certs keystore.jks
```

Use the results with nginx:

```nginx
ssl_certificate     /etc/nginx/certs/tomcat-chain.crt;
ssl_certificate_key /etc/nginx/certs/tomcat.key;
```

Or as a Kubernetes TLS secret:

```sh
kubectl create secret tls my-tls --cert=certs/tomcat-chain.crt --key=certs/tomcat.key
```

### Output files

| File                  | Contents                                                     |
| --------------------- | ------------------------------------------------------------ |
| `<alias>.crt`         | The entry's own (leaf) certificate, PEM                      |
| `<alias>-chain.crt`   | Leaf certificate followed by the intermediates/CA (`-chain`) |
| `<alias>.key`         | Private key, unencrypted PKCS#8 PEM                          |

Characters in the alias that aren't safe in file names are replaced with `_`.

To get an old-style "traditional" RSA key (`-----BEGIN RSA PRIVATE KEY-----`) for software that needs it:

```sh
openssl pkey -in server.key -traditional -out server-rsa.key
```

### Scripting

When stdin isn't a terminal, answers are read one per line, so the tool can be driven from a script or CI job:

```sh
printf '%s\n' "$KEYSTORE_PASSWORD" | jksextract -alias server keystore.jks
```

The order is: keystore password, alias (only if `-alias` isn't given), key password (only if the key uses a different password).

## Limitations

- **JKS only.** PKCS#12 keystores (`.p12`, `.pfx`, and the default for `keytool` since Java 9) can be read directly with OpenSSL; the tool detects them and prints the commands. JCEKS keystores need converting to JKS first with `keytool -importkeystore`.
- **Passwords must use Latin-1 characters** (ASCII plus accented Western European letters). This matches how almost all JKS files are created; other characters are rejected with a clear error.
- One alias per run.

## Security notes

- The extracted private key is written **unencrypted**. Treat it like a password: keep it out of source control (the included `.gitignore` excludes `*.key`, `*.jks`, `*.pem` and similar), restrict who can read it, and delete copies you no longer need.
- On macOS and Linux the key file is created with `0600` permissions. On Windows it inherits the permissions of the folder it's written to, so write it somewhere only you can read.
- Passwords are read without echo and cleared from memory after use, as far as Go allows.

Please report security problems privately via [GitHub security advisories](https://github.com/chasd00/jksextract/security/advisories/new) rather than in a public issue.

## Contributing

Issues and pull requests are welcome.

1. Fork the repository and create a branch.
2. Make your change and add a test for it where practical.
3. Run `gofmt -w .`, `go vet ./...` and `go test ./...`.
4. Open a pull request describing what changed and why.

### Project layout

| File            | Purpose                                                     |
| --------------- | ----------------------------------------------------------- |
| `main.go`       | Flags, the interactive flow, alias selection               |
| `keystore.go`   | Loading the JKS, decrypting entries, format detection      |
| `prompt.go`     | Password and alias prompts (no-echo on terminals)          |
| `output.go`     | Writing PEM files and the summary                          |
| `*_test.go`     | Unit tests (keystores are generated in the tests)          |
| `Makefile`      | macOS / Linux build targets                                |
| `build.ps1`     | Windows build script                                       |
| `bin/`          | Prebuilt release binaries                                  |

## Acknowledgements

JKS parsing is provided by [keystore-go](https://github.com/pavlo-v-chernykh/keystore-go) (MIT). Terminal handling uses [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) (BSD-3-Clause).

## License

[MIT](LICENSE)
