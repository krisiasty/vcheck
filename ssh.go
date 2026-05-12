package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	xkh "golang.org/x/crypto/ssh/knownhosts"
)

// authConfig collects the auth-related flags. Each enabled source contributes
// an ssh.AuthMethod; the SSH library tries them in order until one succeeds.
type authConfig struct {
	useAgent     bool
	identityPath string // empty = none
	usePassword  bool
}

func buildAuthMethods(c authConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if c.useAgent {
		if m := tryAgentAuth(); m != nil {
			methods = append(methods, m)
		}
	}

	if c.identityPath != "" {
		s, err := loadIdentity(c.identityPath)
		if err != nil {
			return nil, fmt.Errorf("identity file %s: %w", c.identityPath, err)
		}
		if s == nil {
			return nil, fmt.Errorf("identity file %s: passphrase required but none provided", c.identityPath)
		}
		methods = append(methods, ssh.PublicKeys(s))
		slog.Debug("identity file loaded", "path", c.identityPath)
	}

	if c.usePassword {
		pw, err := readPassword("ssh password: ")
		if err != nil {
			return nil, fmt.Errorf("cannot read ssh password: %w", err)
		}
		methods = append(methods, ssh.Password(pw))
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("no usable authentication: pass -agent, -identity, or -password")
	}
	return methods, nil
}

func tryAgentAuth() ssh.AuthMethod {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		slog.Debug("SSH_AUTH_SOCK not set; skipping agent")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := net.Dialer{}
	// #nosec G704 -- SSH_AUTH_SOCK is a trusted user-controlled environment variable used by every SSH client
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		slog.Debug("cannot connect to ssh-agent; skipping", "sock", sock, "err", err.Error())
		return nil
	}
	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		_ = conn.Close()
		slog.Debug("ssh-agent refused listing identities; skipping", "sock", sock, "err", err.Error())
		return nil
	}
	if len(keys) == 0 {
		_ = conn.Close()
		slog.Debug("ssh-agent has no identities; skipping", "sock", sock)
		return nil
	}
	slog.Debug("ssh-agent identities available", "sock", sock, "count", len(keys))
	return ssh.PublicKeysCallback(client.Signers)
}

func loadIdentity(path string) (ssh.Signer, error) {
	// #nosec G304 -- path is supplied by the user via -identity and is the file we are explicitly asked to read
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return s, nil
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		pw, perr := readPassword(fmt.Sprintf("passphrase for %s: ", path))
		if perr != nil {
			return nil, perr
		}
		if pw == "" {
			return nil, nil
		}
		return ssh.ParsePrivateKeyWithPassphrase(data, []byte(pw))
	}
	return nil, err
}

// hostKeyVerifier loads the known_hosts files and returns:
//   - an ssh.HostKeyCallback that verifies against them (with the optional
//     accept-unknown override behind -insecure);
//   - a function that, given the dialed address, returns the list of host-key
//     algorithms recorded in known_hosts for that host. Pinning the SSH
//     client to that list makes Go negotiate the same algorithm OpenSSH
//     would, avoiding spurious "key mismatch" errors on hosts that record
//     multiple key types (RSA + ECDSA + ED25519). Returns nil when there's
//     nothing recorded — the caller should leave HostKeyAlgorithms unset so
//     the SSH library falls back to its default order.
//
// When acceptUnknown is true, hosts not yet recorded are accepted with a
// warning; a key that *differs* from one already recorded still fails, so a
// man-in-the-middle attack against a previously-known host is still detected.
// If no known_hosts file is present, acceptUnknown=true falls back to fully
// unverified (warned) and acceptUnknown=false returns an error.
func hostKeyVerifier(acceptUnknown bool) (ssh.HostKeyCallback, func(addr string) []string, error) {
	var paths []string
	if home, err := os.UserHomeDir(); err == nil {
		userKH := filepath.Join(home, ".ssh", "known_hosts")
		if _, err := os.Stat(userKH); err == nil {
			paths = append(paths, userKH)
		}
	}
	if _, err := os.Stat("/etc/ssh/ssh_known_hosts"); err == nil {
		paths = append(paths, "/etc/ssh/ssh_known_hosts")
	}
	if len(paths) == 0 {
		if acceptUnknown {
			slog.Warn("no known_hosts file present; host key will not be verified (-insecure)")
			// #nosec G106 -- only reached when the user explicitly passes -insecure on a host with no known_hosts file at all
			return ssh.InsecureIgnoreHostKey(), nil, nil
		}
		return nil, nil, fmt.Errorf("no known_hosts file found; ssh into the host once first to record its key, or pass -insecure")
	}
	db, err := knownhosts.NewDB(paths...)
	if err != nil {
		return nil, nil, err
	}
	base := db.HostKeyCallback()
	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return base(hostname, remote, key)
	}
	if acceptUnknown {
		cb = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			err := base(hostname, remote, key)
			if err == nil {
				return nil
			}
			var ke *xkh.KeyError
			if errors.As(err, &ke) && len(ke.Want) == 0 {
				slog.Warn("host key not in known_hosts; accepting due to -insecure",
					"host", hostname, "remote", remote.String(), "fingerprint", ssh.FingerprintSHA256(key))
				return nil
			}
			return err
		}
	}
	algos := func(addr string) []string {
		// Returns the algorithms recorded for `addr` in known_hosts, or an
		// empty slice if the host isn't recorded yet.
		return db.HostKeyAlgorithms(addr)
	}
	return cb, algos, nil
}

type sshKeepAliveSender interface {
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
}

func dial(user, host string, port int, timeout, keepAliveInterval time.Duration, ac authConfig, acceptUnknown bool) (*ssh.Client, error) {
	auth, err := buildAuthMethods(ac)
	if err != nil {
		return nil, err
	}
	hkc, algos, err := hostKeyVerifier(acceptUnknown)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: hkc,
		Timeout:         timeout,
	}
	if algos != nil {
		// Pinning to recorded types avoids mismatches when the server offers
		// multiple host-key types and Go's default order would pick a
		// different one than the entry we have on file. Leave unset (Go
		// default order) when nothing is recorded for this host yet.
		if a := algos(addr); len(a) > 0 {
			cfg.HostKeyAlgorithms = a
			slog.Debug("pinned host-key algorithms from known_hosts", "addr", addr, "algorithms", a)
		}
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	startSSHKeepAlive(client, keepAliveInterval)
	return client, nil
}

func startSSHKeepAlive(client sshKeepAliveSender, interval time.Duration) {
	if interval <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if _, _, err := client.SendRequest("keepalive@openssh.com", false, nil); err != nil {
				slog.Debug("ssh keepalive stopped", "err", err.Error())
				return
			}
		}
	}()
}
