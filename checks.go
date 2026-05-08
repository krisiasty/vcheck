package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"strings"
)

// vuln describes a vulnerability checked by vcheck. afAlg adds an extra
// `ss --af-alg` socket scan (only meaningful for the algif_aead family).
type vuln struct {
	cve     string
	name    string
	modules []string
	afAlg   bool
}

var vulns = []vuln{
	{cve: "CVE-2026-31431", name: "Copy Fail", modules: []string{"algif_aead"}, afAlg: true},
	{cve: "CVE-2026-43284", name: "Dirty Frag", modules: []string{"esp4", "esp6", "rxrpc"}},
}

type moduleStatus struct {
	name        string
	loaded      bool
	blacklisted bool
	logTraces   []string
	afAlgSocks  []string
}

type vulnFindings struct {
	vuln    vuln
	modules []moduleStatus
}

func runChecks(s *sudoRunner) ([]vulnFindings, error) {
	loaded, err := loadedModules(s)
	if err != nil {
		return nil, fmt.Errorf("lsmod: %w", err)
	}
	slog.Debug("loaded modules retrieved", "count", len(loaded))

	out := make([]vulnFindings, 0, len(vulns))
	for _, v := range vulns {
		slog.Info("checking vulnerability", "cve", v.cve, "name", v.name)
		f := vulnFindings{vuln: v}

		var afSocks []string
		if v.afAlg {
			afSocks, err = afAlgSockets(s)
			if err != nil {
				return nil, fmt.Errorf("ss --af-alg: %w", err)
			}
			slog.Debug("af_alg sockets", "cve", v.cve, "count", len(afSocks))
		}

		for _, m := range v.modules {
			ms := moduleStatus{name: m}
			if _, ok := loaded[m]; ok {
				ms.loaded = true
			}
			slog.Debug("module loaded check", "module", m, "loaded", ms.loaded)

			bl, err := isBlacklisted(s, m)
			if err != nil {
				return nil, fmt.Errorf("blacklist check %s: %w", m, err)
			}
			ms.blacklisted = bl
			slog.Debug("module blacklist check", "module", m, "blacklisted", bl)

			traces, err := kernelLogTraces(s, m)
			if err != nil {
				return nil, fmt.Errorf("kernel log %s: %w", m, err)
			}
			ms.logTraces = traces
			slog.Debug("module log trace check", "module", m, "lines", len(traces))
			for _, line := range traces {
				slog.Debug("log trace", "module", m, "line", line)
			}

			if v.afAlg {
				ms.afAlgSocks = afSocks
			}
			f.modules = append(f.modules, ms)
		}
		out = append(out, f)
	}
	return out, nil
}

func loadedModules(s *sudoRunner) (map[string]struct{}, error) {
	stdout, stderr, code, err := s.run("/usr/sbin/lsmod 2>/dev/null || /sbin/lsmod 2>/dev/null || lsmod")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("lsmod exit %d: %s", code, strings.TrimSpace(stderr))
	}
	out := make(map[string]struct{})
	sc := bufio.NewScanner(strings.NewReader(stdout))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		out[f[0]] = struct{}{}
	}
	return out, nil
}

func isBlacklisted(s *sudoRunner, mod string) (bool, error) {
	// Match the playbook's signature: `install <mod> /bin/false` lines anywhere
	// in /etc/modprobe.d. Allow leading whitespace and arbitrary spacing.
	pattern := fmt.Sprintf(`^[[:space:]]*install[[:space:]]+%s[[:space:]]+/bin/false`, mod)
	cmd := fmt.Sprintf("grep -r -E -h %s /etc/modprobe.d/ 2>/dev/null", shellQuote(pattern))
	_, _, code, err := s.run(cmd)
	if err != nil {
		return false, err
	}
	// grep: 0 = match, 1 = no match, 2 = error (treated as not found here)
	return code == 0, nil
}

func kernelLogTraces(s *sudoRunner, mod string) ([]string, error) {
	// Prefer journalctl -k (journald systems); fall back to /var/log/kern.log
	// where it exists. Both pipelines are joined so whichever produces output wins.
	cmd := fmt.Sprintf(
		`{ journalctl -k --no-pager -q 2>/dev/null; cat /var/log/kern.log 2>/dev/null; } | grep -i %s | tail -n 5`,
		shellQuote(mod),
	)
	stdout, _, code, err := s.run(cmd)
	if err != nil {
		return nil, err
	}
	// Trailing tail can yield exit 0 even with no matches; grep yields 1 on no match.
	if code != 0 && code != 1 {
		return nil, fmt.Errorf("log query exit %d", code)
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		if t := sc.Text(); t != "" {
			lines = append(lines, t)
		}
	}
	return lines, nil
}

func afAlgSockets(s *sudoRunner) ([]string, error) {
	stdout, _, code, err := s.run("ss -p --af-alg 2>/dev/null | grep -v '^Netid'")
	if err != nil {
		return nil, err
	}
	if code != 0 && code != 1 {
		return nil, fmt.Errorf("ss --af-alg exit %d", code)
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			lines = append(lines, t)
		}
	}
	return lines, nil
}

func classifyFindings(findings []vulnFindings) int {
	var anyVuln, anyUnmit bool
	for _, f := range findings {
		for _, m := range f.modules {
			afActive := len(m.afAlgSocks) > 0
			switch {
			case m.loaded && m.blacklisted:
				// Boot-time mitigation is in place but the kernel still has the
				// module loaded — needs `modprobe -r` or a reboot.
				anyVuln = true
				slog.Error("blacklisted but currently loaded; run 'modprobe -r' or reboot",
					"cve", f.vuln.cve, "module", m.name)
			case m.loaded || afActive:
				// Active right now and not blacklisted — fully vulnerable.
				anyVuln = true
				attrs := []any{"cve", f.vuln.cve, "module", m.name}
				if m.loaded {
					attrs = append(attrs, "loaded", true)
				}
				if afActive {
					attrs = append(attrs, "active_sockets", len(m.afAlgSocks))
				}
				if len(m.logTraces) > 0 {
					attrs = append(attrs, "log_traces", len(m.logTraces))
				}
				slog.Error("VULNERABLE", attrs...)
			case !m.blacklisted:
				anyUnmit = true
				slog.Error("module not blacklisted", "cve", f.vuln.cve, "module", m.name)
			case len(m.logTraces) > 0:
				// Blacklisted, not loaded, but kernel logs show past activity —
				// no current exposure, just a historical signal worth noting.
				slog.Warn("mitigated; past activity detected in kernel logs",
					"cve", f.vuln.cve, "module", m.name, "log_traces", len(m.logTraces))
			default:
				slog.Info("mitigated", "cve", f.vuln.cve, "module", m.name)
			}
		}
	}
	switch {
	case anyVuln:
		return exitVulnerable
	case anyUnmit:
		return exitUnmitigated
	default:
		return exitOK
	}
}

// applyFix writes /etc/modprobe.d/<cve>-disable.conf for every vuln that has at
// least one un-blacklisted module. Returns the count of snippets written.
func applyFix(s *sudoRunner, findings []vulnFindings) (int, error) {
	written := 0
	for _, f := range findings {
		var todo []string
		for _, m := range f.modules {
			if !m.blacklisted {
				todo = append(todo, m.name)
			}
		}
		if len(todo) == 0 {
			slog.Debug("fix: vuln already fully mitigated", "cve", f.vuln.cve)
			continue
		}
		slug := strings.ToLower(strings.ReplaceAll(f.vuln.cve, " ", "-"))
		path := fmt.Sprintf("/etc/modprobe.d/%s-disable.conf", slug)

		var content strings.Builder
		fmt.Fprintf(&content, "# %s — %s\n", f.vuln.cve, f.vuln.name)
		fmt.Fprintf(&content, "# generated by vcheck\n")
		for _, m := range todo {
			fmt.Fprintf(&content, "install %s /bin/false\n", m)
		}

		slog.Info("writing modprobe.d snippet", "path", path, "modules", todo)
		if err := writeRootFile(s, path, content.String()); err != nil {
			return written, fmt.Errorf("write %s: %w", path, err)
		}
		written++
	}
	return written, nil
}

func writeRootFile(s *sudoRunner, path, content string) error {
	cmd := fmt.Sprintf("install -m 0644 -o root -g root /dev/stdin %s", shellQuote(path))
	_, stderr, code, err := s.runStdin(cmd, strings.NewReader(content))
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("install exit %d: %s", code, strings.TrimSpace(stderr))
	}
	return nil
}
