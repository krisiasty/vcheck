package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// sudoRunner runs commands as root over an SSH connection. It detects whether
// passwordless sudo is configured; if not, it prompts once for a password and
// feeds it via `sudo -S` on every subsequent invocation.
type sudoRunner struct {
	client         *ssh.Client
	passwordless   bool
	password       string
	commandTimeout time.Duration
}

func newSudoRunner(client *ssh.Client, commandTimeout time.Duration) (*sudoRunner, error) {
	s := &sudoRunner{client: client, commandTimeout: commandTimeout}
	if err := s.tryPasswordless(); err == nil {
		s.passwordless = true
		return s, nil
	}
	pw, err := readPassword("[sudo] password: ")
	if err != nil {
		return nil, fmt.Errorf("cannot read sudo password: %w", err)
	}
	s.password = pw
	_, stderr, code, err := s.run("true")
	if err != nil {
		return nil, fmt.Errorf("sudo authentication failed: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("sudo authentication failed: exit %d: %s", code, strings.TrimSpace(stderr))
	}
	return s, nil
}

func (s *sudoRunner) tryPasswordless() error {
	sess, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()
	return runSSHSession(sess, "sudo -n true 2>/dev/null", s.commandTimeout)
}

func readPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("stdin is not a terminal; cannot prompt for password")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// run executes cmd as root via sudo. Returns stdout, stderr, exit code, and an
// error only for transport/session failures (a non-zero exit is *not* an error).
func (s *sudoRunner) run(cmd string) (string, string, int, error) {
	return s.runStdin(cmd, nil)
}

// runStdin is like run but pipes extraStdin to the command. When sudo requires
// a password, it is sent as the first stdin line; sudo consumes that line and
// the remainder reaches the child process unchanged.
func (s *sudoRunner) runStdin(cmd string, extraStdin io.Reader) (string, string, int, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return "", "", -1, err
	}
	defer func() { _ = sess.Close() }()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	var stdin bytes.Buffer
	if !s.passwordless {
		stdin.WriteString(s.password)
		stdin.WriteByte('\n')
	}
	if extraStdin != nil {
		if _, err := io.Copy(&stdin, extraStdin); err != nil {
			return "", "", -1, err
		}
	}
	sess.Stdin = &stdin

	err = runSSHSession(sess, buildSudoCmd(s.passwordless, cmd), s.commandTimeout)
	if err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			return stdout.String(), stderr.String(), ee.ExitStatus(), nil
		}
		return stdout.String(), stderr.String(), -1, err
	}
	return stdout.String(), stderr.String(), 0, nil
}

func runSSHSession(sess *ssh.Session, cmd string, timeout time.Duration) error {
	if timeout <= 0 {
		return sess.Run(cmd)
	}
	if err := sess.Start(cmd); err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		done <- sess.Wait()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		return err
	case <-timer.C:
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		return fmt.Errorf("remote command timed out after %s", timeout)
	}
}

func buildSudoCmd(passwordless bool, cmd string) string {
	quoted := shellQuote(cmd)
	if passwordless {
		return "sudo -n sh -c " + quoted
	}
	// -S: read password from stdin; -p '': suppress sudo's own prompt.
	return "sudo -S -p '' sh -c " + quoted
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
