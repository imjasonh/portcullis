package gate

import (
	"bytes"
	"testing"
)

func TestValidate_ValidScript(t *testing.T) {
	script := []byte("#!/bin/bash\necho hello world\n")
	var stderr bytes.Buffer
	if err := Validate(script, &stderr); err != nil {
		t.Errorf("expected valid script to pass, got: %v", err)
	}
}

func TestValidate_ValidScriptNoShebang(t *testing.T) {
	script := []byte("set -euo pipefail\necho hello\nexport FOO=bar\n")
	var stderr bytes.Buffer
	if err := Validate(script, &stderr); err != nil {
		t.Errorf("expected valid script to pass, got: %v", err)
	}
}

func TestValidate_BinaryInput(t *testing.T) {
	binary := []byte{0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01, 0x02}
	var stderr bytes.Buffer
	if err := Validate(binary, &stderr); err == nil {
		t.Error("expected binary input to be blocked")
	}
}

func TestValidate_HTMLErrorPage(t *testing.T) {
	html := []byte(`<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body>
</html>
`)
	var stderr bytes.Buffer
	if err := Validate(html, &stderr); err == nil {
		t.Error("expected HTML to be blocked as non-shell")
	}
}

func TestValidate_MalformedShell(t *testing.T) {
	script := []byte("#!/bin/bash\nif true; then\necho missing fi\n")
	var stderr bytes.Buffer
	if err := Validate(script, &stderr); err == nil {
		t.Error("expected malformed shell to be blocked")
	}
}

func TestComputeHash(t *testing.T) {
	data := []byte("hello\n")
	hash := ComputeHash(data)
	expected := "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	if hash != expected {
		t.Errorf("expected hash %s, got %s", expected, hash)
	}
}

func TestGate_Run_ValidScript(t *testing.T) {
	g := New()
	script := []byte("#!/bin/bash\necho hello\n")
	var stdout, stderr bytes.Buffer
	if err := g.Run(script, &stdout, &stderr); err != nil {
		t.Errorf("expected valid script to pass through gate, got: %v", err)
	}
	if stdout.String() != string(script) {
		t.Errorf("expected stdout to contain script, got: %q", stdout.String())
	}
}

func TestGate_Run_Binary(t *testing.T) {
	g := New()
	binary := []byte{0x7f, 0x45, 0x4c, 0x46, 0x00}
	var stdout, stderr bytes.Buffer
	if err := g.Run(binary, &stdout, &stderr); err == nil {
		t.Error("expected binary to be blocked")
	}
}
