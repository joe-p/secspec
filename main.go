// Command secspec audits and writes security-related settings across services
// from a single JSON spec.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/joe-p/secspec/internal/engine"
	"github.com/joe-p/secspec/internal/spec"
)

const usage = `secspec - audit security settings across services from a spec file

Usage:
  secspec [flags] <command>

Commands:
  diff     Print settings in the spec that do not match reality (exit 0 unless error)
  audit    Check settings and exit non-zero if any mismatch is found
  write    Create and update the settings defined in the spec (never deletes)

Flags:
  --spec <path>          Path to the sec spec file (default "secspec.json")
  --json                 Emit a JSON report
  --github-token <tok>   GitHub token (default $GH_TOKEN, then $GITHUB_TOKEN)
  --github-api-url <u>   GitHub API base URL (default $GITHUB_API_URL)
  --npm-token <tok>      npm token (default $NPM_TOKEN)
  --npm-registry <url>   npm registry URL (default $NPM_REGISTRY)
  --npm-otp <otp>        npm one-time password for 2FA (default $NPM_OTP)
  --non-interactive      Never prompt for an npm OTP; fail instead (e.g. in CI)

When the npm registry requests 2FA and no --npm-otp/NPM_OTP is set, secspec
prompts on the terminal for a code. This is skipped when --non-interactive is
given or when no terminal is available, in which case it exits with an error
asking for NPM_OTP.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("secspec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }

	specPath := fs.String("spec", "secspec.json", "path to the sec spec file")
	jsonOut := fs.Bool("json", false, "emit a JSON report")
	githubToken := fs.String("github-token", "", "GitHub token")
	githubAPIURL := fs.String("github-api-url", "", "GitHub API base URL")
	npmToken := fs.String("npm-token", "", "npm token")
	npmRegistry := fs.String("npm-registry", "", "npm registry URL")
	npmOTP := fs.String("npm-otp", "", "npm one-time password")
	nonInteractive := fs.Bool("non-interactive", false, "never prompt for an npm OTP; fail instead")

	// Parse flags that appear before the command.
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 2
	}
	command := rest[0]
	// Parse any flags that appear after the command.
	if len(rest) > 1 {
		if err := fs.Parse(rest[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
	}

	opts := engine.Options{
		GitHubToken:   firstNonEmpty(*githubToken, os.Getenv("GH_TOKEN"), os.Getenv("GITHUB_TOKEN")),
		GitHubBaseURL: firstNonEmpty(*githubAPIURL, os.Getenv("GITHUB_API_URL")),
		NPMToken:      firstNonEmpty(*npmToken, os.Getenv("NPM_TOKEN")),
		NPMRegistry:   firstNonEmpty(*npmRegistry, os.Getenv("NPM_REGISTRY")),
		NPMOTP:        firstNonEmpty(*npmOTP, os.Getenv("NPM_OTP")),
	}

	// Enable interactive OTP prompting unless it is disabled or there is no
	// terminal to prompt on. Prompting reads from /dev/tty so it never consumes
	// stdin or pollutes stdout (which may be carrying a --json report).
	if !*nonInteractive {
		if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			defer tty.Close()
			reader := bufio.NewReader(tty)
			opts.NPMOTPPrompt = func(ctx context.Context) (string, error) {
				return promptOTP(ctx, tty, reader)
			}
		}
	}

	switch command {
	case "diff", "audit":
		s, err := spec.Load(*specPath)
		if err != nil {
			fmt.Fprintln(stderr, "secspec:", err)
			return 1
		}
		rep, err := engine.Run(ctx, s, opts)
		if err != nil {
			fmt.Fprintln(stderr, "secspec:", err)
			return 1
		}
		if *jsonOut {
			if err := rep.WriteJSON(stdout); err != nil {
				fmt.Fprintln(stderr, "secspec:", err)
				return 1
			}
		} else {
			rep.WriteText(stdout)
		}
		if command == "audit" && !rep.OK() {
			return 1
		}
		return 0

	case "write":
		s, err := spec.Load(*specPath)
		if err != nil {
			fmt.Fprintln(stderr, "secspec:", err)
			return 1
		}
		wr, err := engine.Apply(ctx, s, opts)
		if err != nil {
			fmt.Fprintln(stderr, "secspec:", err)
			return 1
		}
		if *jsonOut {
			if err := wr.WriteJSON(stdout); err != nil {
				fmt.Fprintln(stderr, "secspec:", err)
				return 1
			}
		} else {
			wr.WriteText(stdout)
		}
		return 0

	case "help":
		fmt.Fprint(stdout, usage)
		return 0

	default:
		fmt.Fprintf(stderr, "secspec: unknown command %q\n\n", command)
		fs.Usage()
		return 2
	}
}

// promptOTP asks the user for an npm one-time password on the terminal. The
// prompt is written to tty so it does not interfere with stdout.
func promptOTP(ctx context.Context, tty *os.File, reader *bufio.Reader) (string, error) {
	fmt.Fprint(tty, "npm one-time password (2FA): ")

	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := reader.ReadString('\n')
		done <- result{line, err}
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintln(tty)
		return "", ctx.Err()
	case res := <-done:
		code := strings.TrimSpace(res.line)
		if res.err != nil && code == "" {
			return "", res.err
		}
		return code, nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
