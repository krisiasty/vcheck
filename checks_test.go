package main

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
)

type fakeRunner struct {
	runFunc      func(cmd string) (string, string, int, error)
	runStdinFunc func(cmd string, extraStdin io.Reader) (string, string, int, error)
}

func (f fakeRunner) run(cmd string) (string, string, int, error) {
	if f.runFunc == nil {
		return "", "", -1, fmt.Errorf("unexpected command: %s", cmd)
	}
	return f.runFunc(cmd)
}

func (f fakeRunner) runStdin(cmd string, extraStdin io.Reader) (string, string, int, error) {
	if f.runStdinFunc == nil {
		return "", "", -1, fmt.Errorf("unexpected stdin command: %s", cmd)
	}
	return f.runStdinFunc(cmd, extraStdin)
}

// On older iproute2 (pre-5.10), ss does not support --af-alg and exits non-zero
// with an "unrecognized option" message on stderr. afAlgSockets must treat this
// as a best-effort miss rather than fail the whole scan: the algif_aead module
// is still covered by the lsmod, modules.builtin, kernel-log, and blacklist
// checks, so dropping this one signal must not abort the run.
func TestAFAlgSocketsSkipsOnSSFailure(t *testing.T) {
	r := fakeRunner{
		runFunc: func(cmd string) (string, string, int, error) {
			if cmd != "ss -p --af-alg" {
				t.Fatalf("unexpected command: %s", cmd)
			}
			return "", "ss: unrecognized option '--af-alg'", 255, nil
		},
	}

	got, err := afAlgSockets(r)
	if err != nil {
		t.Fatalf("afAlgSockets returned error on unsupported ss: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil socket list on unsupported ss, got %v", got)
	}
}

func TestAFAlgSocketsSkipsHeader(t *testing.T) {
	r := fakeRunner{
		runFunc: func(cmd string) (string, string, int, error) {
			if cmd != "ss -p --af-alg" {
				t.Fatalf("unexpected command: %s", cmd)
			}
			return "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nu_str ESTAB 0 0 * 0 * 0\n", "", 0, nil
		},
	}

	got, err := afAlgSockets(r)
	if err != nil {
		t.Fatalf("afAlgSockets returned error: %v", err)
	}
	if len(got) != 1 || got[0] != "u_str ESTAB 0 0 * 0 * 0" {
		t.Fatalf("unexpected sockets: %#v", got)
	}
}

func TestModuleNameFromBuiltinPath(t *testing.T) {
	tests := map[string]string{
		"kernel/crypto/algif-aead.ko":       "algif_aead",
		"kernel/net/rxrpc/rxrpc.ko.zst":     "rxrpc",
		"  kernel/net/xfrm/xfrm_user.ko.xz": "xfrm_user",
		"":                                  "",
	}
	for input, want := range tests {
		if got := moduleNameFromBuiltinPath(input); got != want {
			t.Fatalf("moduleNameFromBuiltinPath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBuiltInModulesCombinesBuiltinFileAndSysfs(t *testing.T) {
	r := fakeRunner{
		runFunc: func(cmd string) (string, string, int, error) {
			switch {
			case strings.Contains(cmd, "modules.builtin"):
				return "kernel/crypto/algif-aead.ko\nkernel/net/rxrpc/rxrpc.ko.zst\n", "", 0, nil
			case strings.HasPrefix(cmd, "for m in"):
				return "esp4\nkafs\n", "", 0, nil
			default:
				return "", "", -1, fmt.Errorf("unexpected command: %s", cmd)
			}
		},
	}

	loaded := map[string]struct{}{"esp4": {}}
	got, err := builtInModules(r, loaded, []string{"algif_aead", "esp4", "rxrpc", "kafs"})
	if err != nil {
		t.Fatalf("builtInModules returned error: %v", err)
	}

	for _, name := range []string{"algif_aead", "rxrpc", "kafs"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("expected %s to be built-in, got %#v", name, got)
		}
	}
	if _, ok := got["esp4"]; ok {
		t.Fatalf("loaded sysfs module should not be classified as built-in: %#v", got)
	}
}

func TestClassifyFindingsTreatsBuiltInAsVulnerable(t *testing.T) {
	got := classifyFindings([]vulnFindings{
		{
			vuln: vulns[0],
			modules: []moduleStatus{
				{name: "algif_aead", builtIn: true, blacklisted: true},
			},
		},
	})
	if got != exitVulnerable {
		t.Fatalf("classifyFindings = %d, want %d", got, exitVulnerable)
	}
}

func TestIsBlacklistedReturnsGrepErrors(t *testing.T) {
	r := fakeRunner{
		runFunc: func(cmd string) (string, string, int, error) {
			if !strings.HasPrefix(cmd, "grep -r -E -h") {
				t.Fatalf("unexpected command: %s", cmd)
			}
			return "", "grep: /etc/modprobe.d: Permission denied", 2, nil
		},
	}

	if _, err := isBlacklisted(r, "algif_aead"); err == nil {
		t.Fatal("expected grep error to be returned")
	}
}

func TestApplyFixAndReportReportsBeforeWriting(t *testing.T) {
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	r := fakeRunner{
		runFunc: func(cmd string) (string, string, int, error) {
			switch {
			case strings.Contains(cmd, "lsmod"):
				return "Module                  Size  Used by\n", "", 0, nil
			case strings.Contains(cmd, "modules.builtin"):
				return "", "", 0, nil
			case strings.HasPrefix(cmd, "for m in"):
				return "", "", 0, nil
			case cmd == "ss -p --af-alg":
				return "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n", "", 0, nil
			case strings.HasPrefix(cmd, "grep -r -E -h"):
				return "", "", 0, nil
			case strings.Contains(cmd, "journalctl"):
				return "", "", 0, nil
			default:
				return "", "", -1, fmt.Errorf("unexpected command: %s", cmd)
			}
		},
		runStdinFunc: func(cmd string, extraStdin io.Reader) (string, string, int, error) {
			if !strings.Contains(cmd, "/etc/modprobe.d/cve-2026-31431-disable.conf") {
				t.Fatalf("unexpected write command: %s", cmd)
			}
			if extraStdin == nil {
				t.Fatal("expected snippet content on stdin")
			}
			return "", "", 0, nil
		},
	}
	findings := []vulnFindings{
		{
			vuln: vulns[0],
			modules: []moduleStatus{
				{name: "algif_aead", loaded: true},
			},
		},
	}

	code, err := applyFixAndReport(r, findings)
	if err != nil {
		t.Fatalf("applyFixAndReport returned error: %v", err)
	}
	if code != exitOK {
		t.Fatalf("applyFixAndReport exit code = %d, want %d", code, exitOK)
	}

	out := logs.String()
	before := strings.Index(out, "findings before fix")
	vulnerable := strings.Index(out, "VULNERABLE")
	write := strings.Index(out, "writing modprobe.d snippet")
	after := strings.Index(out, "findings after fix")
	if before < 0 || vulnerable < 0 || write < 0 || after < 0 {
		t.Fatalf("expected pre-fix report, write, and post-fix report in logs:\n%s", out)
	}
	if before >= vulnerable || vulnerable >= write || write >= after {
		t.Fatalf("expected findings before write and post-fix report after write:\n%s", out)
	}
}
