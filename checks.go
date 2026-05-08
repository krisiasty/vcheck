package main

import (
	"bufio"
	"fmt"
	"io"
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

type rootRunner interface {
	run(cmd string) (string, string, int, error)
	runStdin(cmd string, extraStdin io.Reader) (string, string, int, error)
}

var vulns = []vuln{
	{cve: "CVE-2026-31431", name: "Copy Fail", modules: []string{"algif_aead"}, afAlg: true},
	{cve: "CVE-2026-43284", name: "Dirty Frag (IPsec)", modules: []string{"esp4", "esp6", "xfrm_algo", "xfrm_user"}},
	{cve: "CVE-2026-43500", name: "Dirty Frag (RxRPC)", modules: []string{"rxrpc", "kafs"}},
}

type moduleStatus struct {
	name        string
	loaded      bool
	builtIn     bool
	blacklisted bool
	logTraces   []string
	afAlgSocks  []string
}

type vulnFindings struct {
	vuln    vuln
	modules []moduleStatus
}

func runChecks(s rootRunner) ([]vulnFindings, error) {
	loaded, err := loadedModules(s)
	if err != nil {
		return nil, fmt.Errorf("lsmod: %w", err)
	}
	slog.Debug("loaded modules retrieved", "count", len(loaded))

	builtIn, err := builtInModules(s, loaded, targetModules())
	if err != nil {
		return nil, fmt.Errorf("built-in module check: %w", err)
	}
	slog.Debug("built-in modules retrieved", "count", len(builtIn))

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
			if _, ok := builtIn[m]; ok {
				ms.builtIn = true
			}
			slog.Debug("module presence check", "module", m, "loaded", ms.loaded, "built_in", ms.builtIn)

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

func targetModules() []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, v := range vulns {
		for _, m := range v.modules {
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}
	return out
}

func loadedModules(s rootRunner) (map[string]struct{}, error) {
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
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func builtInModules(s rootRunner, loaded map[string]struct{}, modules []string) (map[string]struct{}, error) {
	fromBuiltin, err := modulesBuiltinFile(s)
	if err != nil {
		return nil, err
	}
	fromSys, err := sysModuleDirs(s, modules)
	if err != nil {
		return nil, err
	}

	out := make(map[string]struct{})
	for _, m := range modules {
		if _, ok := fromBuiltin[m]; ok {
			out[m] = struct{}{}
			continue
		}
		if _, ok := fromSys[m]; ok {
			if _, isLoaded := loaded[m]; !isLoaded {
				out[m] = struct{}{}
			}
		}
	}
	return out, nil
}

func modulesBuiltinFile(s rootRunner) (map[string]struct{}, error) {
	stdout, stderr, code, err := s.run(`f=/lib/modules/$(uname -r)/modules.builtin; [ -r "$f" ] && cat "$f" || true`)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("modules.builtin exit %d: %s", code, strings.TrimSpace(stderr))
	}

	out := make(map[string]struct{})
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		if name := moduleNameFromBuiltinPath(sc.Text()); name != "" {
			out[name] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func moduleNameFromBuiltinPath(line string) string {
	name := strings.TrimSpace(line)
	if name == "" {
		return ""
	}
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.Index(name, ".ko"); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return strings.ReplaceAll(name, "-", "_")
}

func sysModuleDirs(s rootRunner, modules []string) (map[string]struct{}, error) {
	if len(modules) == 0 {
		return map[string]struct{}{}, nil
	}

	var cmd strings.Builder
	cmd.WriteString("for m in")
	for _, m := range modules {
		fmt.Fprintf(&cmd, " %s", shellQuote(m))
	}
	cmd.WriteString(`; do [ -d "/sys/module/$m" ] && printf '%s\n' "$m"; done; true`)

	stdout, stderr, code, err := s.run(cmd.String())
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("sysfs module check exit %d: %s", code, strings.TrimSpace(stderr))
	}

	out := make(map[string]struct{})
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		if name := strings.TrimSpace(sc.Text()); name != "" {
			out[name] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func isBlacklisted(s rootRunner, mod string) (bool, error) {
	// Match the playbook's signature: `install <mod> /bin/false` lines anywhere
	// in /etc/modprobe.d. Allow leading whitespace and arbitrary spacing.
	pattern := fmt.Sprintf(`^[[:space:]]*install[[:space:]]+%s[[:space:]]+/bin/false`, mod)
	cmd := fmt.Sprintf("grep -r -E -h %s /etc/modprobe.d/ 2>/dev/null", shellQuote(pattern))
	_, stderr, code, err := s.run(cmd)
	if err != nil {
		return false, err
	}
	switch code {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, fmt.Errorf("grep exit %d: %s", code, strings.TrimSpace(stderr))
	}
}

func kernelLogTraces(s rootRunner, mod string) ([]string, error) {
	// Best-effort historical signal: read journalctl -k and /var/log/kern.log
	// where available, then keep the last few matching lines.
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
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func afAlgSockets(s rootRunner) ([]string, error) {
	stdout, stderr, code, err := s.run("ss -p --af-alg")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		// Best-effort signal — older iproute2 (pre-5.10ish) doesn't support
		// `--af-alg`. Skip silently rather than fail the whole scan; the
		// algif_aead module is still covered by the lsmod, modules.builtin,
		// and modprobe.d blacklist checks.
		msg := strings.TrimSpace(stderr)
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if strings.Contains(msg, "unrecognized option") || strings.Contains(msg, "invalid option") {
			slog.Warn("ss does not support --af-alg on this host; skipping socket enumeration")
		} else {
			slog.Warn("ss --af-alg failed; skipping socket enumeration", "exit", code, "stderr", msg)
		}
		return nil, nil
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			if strings.HasPrefix(t, "Netid") {
				continue
			}
			lines = append(lines, t)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func classifyFindings(findings []vulnFindings) int {
	var anyVuln, anyUnmit bool
	for _, f := range findings {
		for _, m := range f.modules {
			afActive := len(m.afAlgSocks) > 0
			switch {
			case m.builtIn:
				anyVuln = true
				slog.Error("VULNERABLE: module built into kernel; modprobe blacklist cannot mitigate",
					"cve", f.vuln.cve, "module", m.name, "blacklisted", m.blacklisted)
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
// least one un-blacklisted module. The snippet always contains *every* module
// for the CVE so the file is authoritative — partial writes (only the
// currently-missing modules) would overwrite previously-blacklisted entries
// already in our own file. Returns the count of snippets written.
func applyFix(s rootRunner, findings []vulnFindings) (int, error) {
	written := 0
	for _, f := range findings {
		anyMissing := false
		for _, m := range f.modules {
			if !m.blacklisted {
				anyMissing = true
				break
			}
		}
		if !anyMissing {
			slog.Debug("fix: vuln already fully mitigated", "cve", f.vuln.cve)
			continue
		}
		slug := strings.ToLower(strings.ReplaceAll(f.vuln.cve, " ", "-"))
		path := fmt.Sprintf("/etc/modprobe.d/%s-disable.conf", slug)

		var content strings.Builder
		fmt.Fprintf(&content, "# %s — %s\n", f.vuln.cve, f.vuln.name)
		fmt.Fprintf(&content, "# generated by vcheck\n")
		for _, m := range f.vuln.modules {
			fmt.Fprintf(&content, "install %s /bin/false\n", m)
		}

		slog.Info("writing modprobe.d snippet", "path", path, "modules", f.vuln.modules)
		if err := writeRootFile(s, path, content.String()); err != nil {
			return written, fmt.Errorf("write %s: %w", path, err)
		}
		written++
	}
	return written, nil
}

func writeRootFile(s rootRunner, path, content string) error {
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
