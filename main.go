package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
)

var (
	version = "dev (unreleased)"
	commit  = "none"
	date    = "unknown"
)

const (
	exitOK          = 0
	exitUsage       = 1
	exitConn        = 2
	exitSudo        = 3
	exitUnmitigated = 4
	exitVulnerable  = 5
	exitInternal    = 99
)

func main() {
	var (
		host           string
		user           string
		port           int
		useAgent       bool
		identity       string
		usePassword    bool
		fix            bool
		debug          bool
		showVer        bool
		insecure       bool
		skipLogs       bool
		connectTimeout time.Duration
		commandTimeout time.Duration
	)
	flag.StringVar(&host, "host", "", "remote host (required)")
	flag.StringVar(&user, "user", "", "remote user (default: $USER)")
	flag.IntVar(&port, "port", 22, "remote SSH port")
	flag.BoolVar(&useAgent, "agent", true, "use SSH agent for authentication")
	flag.StringVar(&identity, "identity", "", "path to private key file")
	flag.BoolVar(&usePassword, "password", false, "prompt for an SSH password")
	flag.BoolVar(&fix, "fix", false, "write /etc/modprobe.d snippets disabling affected modules")
	flag.BoolVar(&debug, "debug", false, "increase log verbosity")
	flag.BoolVar(&showVer, "version", false, "show version and exit")
	flag.BoolVar(&insecure, "insecure", false, "accept host keys not yet recorded in known_hosts; mismatches with a recorded key still fail")
	flag.BoolVar(&skipLogs, "skip-logs", false, "skip kernel log history checks")
	flag.DurationVar(&connectTimeout, "timeout", 15*time.Second, "SSH connect timeout")
	flag.DurationVar(&commandTimeout, "command-timeout", 30*time.Second, "remote command timeout (0 disables)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"usage: %s -host HOST [flags]\n\n"+
				"checks remote host for Copy Fail (CVE-2026-31431) and Dirty Frag\n"+
				"(CVE-2026-43284, CVE-2026-43500) kernel-module exposure.\n\nflags:\n",
			os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if showVer {
		fmt.Printf("vcheck %s (%s, %s)\n", version, commit, date)
		return
	}

	initLog(debug)

	if host == "" {
		flag.Usage()
		os.Exit(exitUsage)
	}
	if port <= 0 || port > 65535 {
		slog.Error("invalid port", "port", port)
		os.Exit(exitUsage)
	}
	if connectTimeout < 0 || commandTimeout < 0 {
		slog.Error("timeout values cannot be negative", "timeout", connectTimeout, "command_timeout", commandTimeout)
		os.Exit(exitUsage)
	}
	if user == "" {
		user = os.Getenv("USER")
		if user == "" {
			slog.Error("user is empty and $USER is unset; pass -user")
			os.Exit(exitUsage)
		}
	}
	slog.Debug("target", "user", user, "host", host, "port", port)

	ac := authConfig{useAgent: useAgent, identityPath: identity, usePassword: usePassword}
	client, err := dial(user, host, port, connectTimeout, ac, insecure)
	if err != nil {
		slog.Error("ssh connection failed", "host", host, "port", port, "err", err.Error())
		os.Exit(exitConn)
	}
	defer func() { _ = client.Close() }()
	slog.Info("connected", "user", user, "host", host, "port", port)

	sudo, err := newSudoRunner(client, commandTimeout)
	if err != nil {
		slog.Error("sudo setup failed", "err", err.Error())
		os.Exit(exitSudo)
	}
	if sudo.passwordless {
		slog.Debug("sudo: passwordless")
	} else {
		slog.Debug("sudo: password authenticated")
	}

	checkOpts := checkOptions{skipLogs: skipLogs}
	findings, err := runChecks(sudo, checkOpts)
	if err != nil {
		slog.Error("check execution failed", "err", err.Error())
		os.Exit(exitInternal)
	}

	if fix {
		exitCode, err := applyFixAndReport(sudo, findings, checkOpts)
		if err != nil {
			slog.Error("fix failed", "err", err.Error())
			os.Exit(exitInternal)
		}
		os.Exit(exitCode)
	}

	os.Exit(classifyFindings(findings))
}

func applyFixAndReport(s rootRunner, findings []vulnFindings, opts checkOptions) (int, error) {
	slog.Info("findings before fix")
	exitCode := classifyFindings(findings)

	written, err := applyFix(s, findings)
	if err != nil {
		return 0, err
	}
	if written == 0 {
		slog.Info("fix: nothing to do — all affected modules already blacklisted")
		return exitCode, nil
	}

	slog.Info("re-scanning after fix", "snippets_written", written)
	findings, err = runChecks(s, opts)
	if err != nil {
		return 0, fmt.Errorf("post-fix check execution failed: %w", err)
	}

	slog.Info("findings after fix")
	return classifyFindings(findings), nil
}

func initLog(debug bool) {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		Level:      level,
		TimeFormat: time.StampMilli,
		NoColor:    !isatty.IsTerminal(os.Stderr.Fd()),
	})))
	slog.Debug(fmt.Sprintf("log level: %v", level))
}
