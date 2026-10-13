package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// prompter asks questions on stderr and reads answers from stdin. When stdin
// is a terminal, passwords are read without echo; otherwise (piped input, CI)
// answers are read line by line so the tool can still be scripted.
type prompter struct {
	in    *os.File
	out   io.Writer
	isTTY bool
	r     *bufio.Reader
}

func newPrompter(in *os.File, out io.Writer) *prompter {
	return &prompter{
		in:    in,
		out:   out,
		isTTY: term.IsTerminal(int(in.Fd())),
		r:     bufio.NewReader(in),
	}
}

func (p *prompter) line(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	s, err := p.r.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && s != "") {
		if errors.Is(err, io.EOF) {
			return "", errors.New("no input")
		}
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// password reads a password without echoing it and returns it in the form
// Java uses for JKS passwords (see toJavaPassword).
func (p *prompter) password(prompt string) ([]byte, error) {
	var raw []byte
	if p.isTTY {
		fmt.Fprint(p.out, prompt)
		b, err := term.ReadPassword(int(p.in.Fd()))
		fmt.Fprintln(p.out)
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		raw = b
	} else {
		s, err := p.line(prompt)
		fmt.Fprintln(p.out) // piped input isn't echoed, so end the prompt line
		if err != nil {
			return nil, err
		}
		raw = []byte(s)
	}
	defer zero(raw)
	return toJavaPassword(raw)
}

// toJavaPassword converts UTF-8 input to the one-byte-per-character form the
// keystore library expects. JKS hashes passwords as Java chars; the library
// widens each byte to a char, which is correct for characters up to U+00FF
// (ASCII and Latin-1) once the UTF-8 encoding is undone.
func toJavaPassword(utf8Pass []byte) ([]byte, error) {
	out := make([]byte, 0, len(utf8Pass))
	for len(utf8Pass) > 0 {
		r, size := utf8.DecodeRune(utf8Pass)
		if r == utf8.RuneError && size == 1 {
			zero(out)
			return nil, errors.New("password is not valid UTF-8")
		}
		if r > 0xFF {
			zero(out)
			return nil, errors.New("passwords containing characters beyond Latin-1 are not supported")
		}
		out = append(out, byte(r))
		utf8Pass = utf8Pass[size:]
	}
	return out, nil
}
