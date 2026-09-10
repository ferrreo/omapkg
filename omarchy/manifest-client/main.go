package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

const version = "manifest-client-v1"

type cliFlags struct {
	manifest     string
	discovery    string
	origin       string
	channel      string
	signature    string
	key          string
	fingerprint  string
	config       string
	state        string
	stage        string
	pacman       string
	architecture string
	allowHTTP    bool
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		usage()
		return 0
	}
	if args[0] == "--version" {
		fmt.Println(version)
		return 0
	}
	switch args[0] {
	case "stage":
		return runStage(args[1:])
	case "apply":
		return runApply(args[1:])
	case "show":
		return runShow(args[1:], false)
	case "recovery":
		return runShow(args[1:], true)
	case "image-lock":
		return runImageLock(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		usage()
		return 2
	}
}

func runStage(args []string) int {
	flags, apply, ok := parseCommon(args, true)
	if !ok || (flags.manifest == "" && flags.discovery == "" && flags.origin == "") {
		return 2
	}
	client, err := newClient(flags)
	if err != nil {
		return fail(err)
	}
	ctx := context.Background()
	tx, plan, err := client.Stage(ctx, TransactionOptions{ManifestURL: flags.manifest, DiscoveryURL: flags.discovery, ConfigPath: flags.config, StatePath: flags.state, StageDir: flags.stage, Pacman: flags.pacman})
	if err != nil {
		return fail(err)
	}
	fmt.Print(plan)
	if !apply {
		fmt.Fprintf(os.Stderr, "\nStaged %s. Review %s, then run `omarchy-manifest-client apply`.\n", tx.Digest, flags.stage+"/transaction-plan.txt")
		return 0
	}
	_, err = client.Apply(ctx, TransactionOptions{ConfigPath: flags.config, StatePath: flags.state, StageDir: flags.stage, Pacman: flags.pacman})
	if err != nil {
		return fail(err)
	}
	fmt.Fprintln(os.Stderr, "Applied reviewed manifest transaction.")
	return 0
}

func runApply(args []string) int {
	flags, _, ok := parseCommon(args, false)
	if !ok {
		return 2
	}
	client, err := newClient(flags)
	if err != nil {
		return fail(err)
	}
	_, err = client.Apply(context.Background(), TransactionOptions{ConfigPath: flags.config, StatePath: flags.state, StageDir: flags.stage, Pacman: flags.pacman})
	if err != nil {
		return fail(err)
	}
	fmt.Println("Applied reviewed manifest transaction.")
	return 0
}

func runShow(args []string, recovery bool) int {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	statePath := fs.String("state", "/var/lib/omarchy/manifest-state.json", "local durable manifest state")
	stagePath := fs.String("stage-dir", "/var/lib/omarchy/manifest-stage", "staged transaction directory")
	channel := fs.String("channel", "", "channel to inspect (stable, rc, or edge)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	state, err := readState(*statePath)
	if err != nil {
		return fail(err)
	}
	if *channel != "" && !channelPattern.MatchString(*channel) {
		return fail(errors.New("channel must be stable, rc, or edge"))
	}
	if *channel != "" {
		state = stateForChannel(state, *channel)
	}
	if state.SchemaVersion == 0 {
		return fail(errors.New("no manifest transaction has been applied"))
	}
	if recovery {
		if state.RecoveryTarget == "" || state.RecoveryLimits == "" {
			return fail(errors.New("no signed recovery plan is recorded"))
		}
		fmt.Printf("Recovery target: %s\nConstraints: %s\n", state.RecoveryTarget, state.RecoveryLimits)
		fmt.Println("Automatic downgrade is blocked; stage a newer signed recovery transaction with its authorization.")
		return 0
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fail(err)
	}
	fmt.Println(string(data))
	plan, err := os.ReadFile(*stagePath + "/transaction-plan.txt")
	if err == nil {
		fmt.Printf("\nLast staged plan:\n%s", plan)
	}
	return 0
}

func parseCommon(args []string, includeManifest bool) (cliFlags, bool, bool) {
	fs := flag.NewFlagSet("manifest-client", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	flags := cliFlags{}
	fs.StringVar(&flags.manifest, "manifest", "", "resolved transaction manifest URL")
	fs.StringVar(&flags.signature, "signature", "", "detached OpenPGP signature URL for manifest")
	fs.StringVar(&flags.channel, "channel", "", "expected channel (stable, rc, or edge)")
	fs.StringVar(&flags.discovery, "discovery", "", "mutable channel discovery URL")
	fs.StringVar(&flags.origin, "origin", "", "repository origin for built-in channel discovery")
	fs.StringVar(&flags.key, "key", "", "trusted OpenPGP public key file")
	fs.StringVar(&flags.fingerprint, "fingerprint", "", "trusted OpenPGP fingerprint")
	fs.StringVar(&flags.config, "config", "/etc/pacman.conf", "pacman config path")
	fs.StringVar(&flags.state, "state", "/var/lib/omarchy/manifest-state.json", "local durable manifest state")
	fs.StringVar(&flags.stage, "stage-dir", "/var/lib/omarchy/manifest-stage", "staged transaction directory")
	fs.StringVar(&flags.pacman, "pacman", "pacman", "pacman executable")
	fs.StringVar(&flags.architecture, "arch", "", "target architecture (x86_64 or aarch64)")
	fs.BoolVar(&flags.allowHTTP, "allow-http", false, "allow HTTP only for local fixture tests")
	apply := false
	if includeManifest {
		fs.BoolVar(&apply, "apply", false, "apply transaction after staging; requires explicit use")
	}
	if err := fs.Parse(args); err != nil {
		return flags, apply, false
	}
	if flags.key == "" || flags.fingerprint == "" {
		fmt.Fprintln(os.Stderr, "--key and --fingerprint are required")
		return flags, apply, false
	}
	if flags.channel != "" && !channelPattern.MatchString(flags.channel) {
		fmt.Fprintln(os.Stderr, "--channel must be stable, rc, or edge")
		return flags, apply, false
	}
	return flags, apply, true
}

func newClient(flags cliFlags) (*Client, error) {
	return New(Options{TrustedKey: flags.key, TrustedFingerprint: strings.TrimSpace(flags.fingerprint), AllowHTTP: flags.allowHTTP, Architecture: flags.architecture, ManifestSignatureURL: flags.signature, ExpectedChannel: flags.channel, DiscoveryOrigin: flags.origin})
}

func fail(err error) int { fmt.Fprintln(os.Stderr, "error:", err); return 1 }

func usage() {
	fmt.Println(`Usage:
  omarchy-manifest-client stage [--manifest URL | --discovery URL | --origin URL] --key FILE --fingerprint HEX [options]
  omarchy-manifest-client apply --key FILE --fingerprint HEX [options]
  omarchy-manifest-client show [--state FILE] [--stage-dir DIR]
  omarchy-manifest-client recovery [--state FILE]
  omarchy-manifest-client image-lock --manifest URL --key FILE --fingerprint HEX --output DIR

stage resolves one channel discovery URL to an immutable signed resolved transaction, then verifies both signed lane manifests and
every repository database before writing an atomic staged pacman config and a
reviewable preview. apply runs one complete pacman sync transaction and commits
the staged config/state only after pacman succeeds. Downgrades require the
signed recovery authorization in the resolved transaction.

image-lock verifies the immutable transaction, system and OPR manifests, then
retains their exact bytes and package chunks for an offline image build.`)
}
