# vcheck

Audit a remote Linux host over SSH for the Copy Fail and Dirty Frag
kernel-module vulnerabilities and, optionally, apply mitigations:

| CVE              | Name                 | Affected modules                              |
| ---------------- | -------------------- | --------------------------------------------- |
| CVE-2026-31431   | Copy Fail            | `algif_aead`                                  |
| CVE-2026-43284   | Dirty Frag (IPsec)   | `esp4`, `esp6`, `xfrm_algo`, `xfrm_user`      |
| CVE-2026-43500   | Dirty Frag (RxRPC)   | `rxrpc`, `kafs`                               |

For each affected module, vcheck reports whether it is currently loaded, has
past traces in kernel logs, has live `AF_ALG` sockets (Copy Fail only), and
whether it is already blacklisted under `/etc/modprobe.d/`.

With `-fix`, vcheck writes a `cve-XXXX-XXXXX-disable.conf` snippet for any module that is not yet
blacklisted, then re-runs the checks and reports the final state.

## Installation

**Homebrew (macOS):**

```bash
brew install krisiasty/tap/vcheck
```

**Pre-built binaries** for Linux, macOS, and Windows are published on the [releases page](https://github.com/krisiasty/vcheck/releases).

**From source** (requires Go 1.26+):

```bash
go install github.com/krisiasty/vcheck@latest
```

## Usage

```text
vcheck -host HOST [flags]
```

| Flag                | Default       | Description                                                                                   |
| ------------------- | ------------- | --------------------------------------------------------------------------------------------- |
| `-host`             | *(required)*  | Remote host                                                                                   |
| `-user`             | `$USER`       | Remote user                                                                                   |
| `-port`             | `22`          | Remote SSH port                                                                               |
| `-agent`            | `true`        | Use SSH agent for authentication                                                              |
| `-identity`         | *(empty)*     | Path to a private key file (prompts for passphrase if encrypted)                              |
| `-password`         | `false`       | Prompt for an SSH password                                                                    |
| `-insecure`         | `false`       | Accept host keys not yet recorded in `known_hosts`; mismatches with a recorded key still fail |
| `-fix`              | `false`       | Write `/etc/modprobe.d` snippets for modules that are not already blacklisted                 |
| `-timeout`          | `15s`         | SSH connect timeout                                                                           |
| `-debug`            | `false`       | Increase log verbosity                                                                        |
| `-version`          | `false`       | Show version and exit                                                                         |

At least one of `-agent`, `-identity`, or `-password` must produce a usable authentication method.
Methods are tried in the order listed.

Sudo is required on the target. If passwordless sudo is configured the tool proceeds silently;
otherwise it prompts once for a password (input is hidden) and feeds it via `sudo -S` for every subsequent command.

## Exit codes

| Code | Meaning                                                                            |
| ---- | ---------------------------------------------------------------------------------- |
| `0`  | All affected modules mitigated (blacklisted, not loaded, no active exposure)       |
| `1`  | Usage error                                                                        |
| `2`  | SSH connection failed                                                              |
| `3`  | Sudo authentication failed                                                         |
| `4`  | One or more modules not blacklisted (no current exposure)                          |
| `5`  | One or more modules currently loaded or actively in use                            |
| `99` | Internal/check failure                                                             |

## Sample output

### Fully mitigated host

```console
$ vcheck -host host.example.com -identity ~/.ssh/id_ed25519
INF connected user=ops host=host.example.com port=22
INF checking vulnerability cve=CVE-2026-31431 name="Copy Fail"
INF checking vulnerability cve=CVE-2026-43284 name="Dirty Frag (IPsec)"
INF checking vulnerability cve=CVE-2026-43500 name="Dirty Frag (RxRPC)"
INF mitigated cve=CVE-2026-31431 module=algif_aead
INF mitigated cve=CVE-2026-43284 module=esp4
INF mitigated cve=CVE-2026-43284 module=esp6
INF mitigated cve=CVE-2026-43284 module=xfrm_algo
INF mitigated cve=CVE-2026-43284 module=xfrm_user
INF mitigated cve=CVE-2026-43500 module=rxrpc
INF mitigated cve=CVE-2026-43500 module=kafs
```

### Unmitigated and partially loaded — bare check

```console
$ vcheck -host host.example.com -identity ~/.ssh/id_ed25519
INF connected user=ops host=host.example.com port=22
INF checking vulnerability cve=CVE-2026-31431 name="Copy Fail"
INF checking vulnerability cve=CVE-2026-43284 name="Dirty Frag (IPsec)"
INF checking vulnerability cve=CVE-2026-43500 name="Dirty Frag (RxRPC)"
INF mitigated cve=CVE-2026-31431 module=algif_aead
ERR VULNERABLE cve=CVE-2026-43284 module=esp4 loaded=true
ERR module not blacklisted cve=CVE-2026-43284 module=esp6
ERR module not blacklisted cve=CVE-2026-43284 module=xfrm_algo
ERR module not blacklisted cve=CVE-2026-43284 module=xfrm_user
ERR module not blacklisted cve=CVE-2026-43500 module=rxrpc
ERR module not blacklisted cve=CVE-2026-43500 module=kafs
```

### Same host with `-fix` — first run

```console
$ vcheck -fix -host host.example.com -identity ~/.ssh/id_ed25519
INF connected user=ops host=host.example.com port=22
INF checking vulnerability cve=CVE-2026-31431 name="Copy Fail"
INF checking vulnerability cve=CVE-2026-43284 name="Dirty Frag (IPsec)"
INF checking vulnerability cve=CVE-2026-43500 name="Dirty Frag (RxRPC)"
INF writing modprobe.d snippet path=/etc/modprobe.d/cve-2026-43284-disable.conf modules="[esp4 esp6 xfrm_algo xfrm_user]"
INF writing modprobe.d snippet path=/etc/modprobe.d/cve-2026-43500-disable.conf modules="[rxrpc kafs]"
INF re-scanning after fix snippets_written=2
INF checking vulnerability cve=CVE-2026-31431 name="Copy Fail"
INF checking vulnerability cve=CVE-2026-43284 name="Dirty Frag (IPsec)"
INF checking vulnerability cve=CVE-2026-43500 name="Dirty Frag (RxRPC)"
INF mitigated cve=CVE-2026-31431 module=algif_aead
ERR blacklisted but currently loaded; run 'modprobe -r' or reboot cve=CVE-2026-43284 module=esp4
INF mitigated cve=CVE-2026-43284 module=esp6
INF mitigated cve=CVE-2026-43284 module=xfrm_algo
INF mitigated cve=CVE-2026-43284 module=xfrm_user
INF mitigated cve=CVE-2026-43500 module=rxrpc
INF mitigated cve=CVE-2026-43500 module=kafs
```

The blacklist is in place, but `esp4` was already loaded into the kernel
before the snippet was written. Reboot or run `sudo modprobe -r esp4` on the
target to fully clear it.

### Second run — esp4 still loaded

```console
$ vcheck -fix -host host.example.com -identity ~/.ssh/id_ed25519
INF connected user=ops host=host.example.com port=22
INF checking vulnerability cve=CVE-2026-31431 name="Copy Fail"
INF checking vulnerability cve=CVE-2026-43284 name="Dirty Frag (IPsec)"
INF checking vulnerability cve=CVE-2026-43500 name="Dirty Frag (RxRPC)"
INF fix: nothing to do — all affected modules already blacklisted
INF mitigated cve=CVE-2026-31431 module=algif_aead
ERR blacklisted but currently loaded; run 'modprobe -r' or reboot cve=CVE-2026-43284 module=esp4
INF mitigated cve=CVE-2026-43284 module=esp6
INF mitigated cve=CVE-2026-43284 module=xfrm_algo
INF mitigated cve=CVE-2026-43284 module=xfrm_user
INF mitigated cve=CVE-2026-43500 module=rxrpc
INF mitigated cve=CVE-2026-43500 module=kafs
```

### Third run — after `modprobe -r esp4`

```console
$ vcheck -host host.example.com -identity ~/.ssh/id_ed25519
INF connected user=ops host=host.example.com port=22
INF checking vulnerability cve=CVE-2026-31431 name="Copy Fail"
INF checking vulnerability cve=CVE-2026-43284 name="Dirty Frag (IPsec)"
INF checking vulnerability cve=CVE-2026-43500 name="Dirty Frag (RxRPC)"
INF mitigated cve=CVE-2026-31431 module=algif_aead
INF mitigated cve=CVE-2026-43284 module=esp4
INF mitigated cve=CVE-2026-43284 module=esp6
INF mitigated cve=CVE-2026-43284 module=xfrm_algo
INF mitigated cve=CVE-2026-43284 module=xfrm_user
INF mitigated cve=CVE-2026-43500 module=rxrpc
INF mitigated cve=CVE-2026-43500 module=kafs
```

### First-time host — `-insecure`

```console
$ vcheck -insecure -host host.example.com -identity ~/.ssh/id_ed25519
WRN host key not in known_hosts; accepting due to -insecure host=host.example.com:22 remote=192.0.2.42:22 fingerprint=SHA256:AAAAEXAMPLEfingerPrint000000000000000000000
INF connected user=ops host=host.example.com port=22
INF checking vulnerability cve=CVE-2026-31431 name="Copy Fail"
...
```

`-insecure` accepts hosts that are not yet in `known_hosts`. If a host *is*
already recorded and presents a different key, the connection still fails —
the flag is only a "first contact" override, not a way to suppress
man-in-the-middle warnings on a known host.

## Detection details

- **Loaded:** `lsmod` is fetched once and module names are matched against the
  first column.
- **Blacklisted:** every file under `/etc/modprobe.d/` is searched (`grep -rE`)
  for an `install <module> /bin/false` directive — the same form vcheck writes
  with `-fix`. Other forms of disabling (e.g. `blacklist`) are not recognized.
- **Past activity:** `journalctl -k` is consulted first, with a fallback to
  `/var/log/kern.log`; the last five matching lines per module are kept.
- **Active sockets (`algif_aead` only):** `ss -p --af-alg` lists open
  `AF_ALG` sockets; any output other than the header counts as live use.

All commands run via `sudo` — privileged access is required to read
`/var/log/kern.log`, list `AF_ALG` sockets, and write under
`/etc/modprobe.d/`.
