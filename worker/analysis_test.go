package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestShellInputsReadableWithPrivateServiceUmask(t *testing.T) {
	directory := t.TempDir()
	runtime := filepath.Join(directory, "runtime")
	script := `#!/bin/sh
set -eu
[ "$1" = run ] || exit 0
count=0
for argument do
  case "$argument" in
    type=bind,src=*,dst=/opr-*,readonly)
      input_file=${argument#type=bind,src=}
      input_file=${input_file%%,dst=*}
      mode=$(stat -c %a "$input_file")
      [ $((0$mode & 4)) -ne 0 ] || exit 126
      [ "$(stat -c %a "$(dirname "$input_file")")" = 700 ] || exit 1
      count=$((count + 1))
      ;;
  esac
done
[ "$count" = 3 ]
printf 'readable\n'
`
	if err := os.WriteFile(runtime, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)
	runner := Runner{Runtime: runtime, StateDir: directory}
	output, err := runner.checkShell(context.Background(), Job{Recipe: "pkgname=demo\n", PublicRecipe: "pkgname=demo\n", SmokeCommands: []string{"true"}}, "umask-test", "fixture-image")
	if err != nil || strings.TrimSpace(output) != "readable" {
		t.Fatalf("lint inputs must be readable by the isolated container user: %v %s", err, output)
	}
}
