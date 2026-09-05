#!/bin/sh
set -eu

usage() {
  cat >&2 <<'EOF'
usage: install.sh --binary PATH --version VERSION --sha256 SHA256 [options]
  --prefix PATH       install prefix (default /usr/local)
  --state-dir PATH    private worker state (default /var/lib/opr-worker)
  --unit-dir PATH     systemd unit directory (default /etc/systemd/system)
  --user NAME         service user (default opr-worker)
  --group NAME        service group (default opr-worker)
  --enable            enable service at boot
  --start             start service after install
  --restart           restart service after install
  --replace-unit      replace an existing different unit file
EOF
  exit 2
}

die() {
  printf 'opr-worker install: %s\n' "$1" >&2
  exit 1
}

binary=
version=
expected_sha256=
prefix=/usr/local
state_dir=/var/lib/opr-worker
unit_dir=/etc/systemd/system
service_user=opr-worker
service_group=opr-worker
enable=0
start=0
restart=0
replace_unit=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) [ "$#" -ge 2 ] || usage; binary=$2; shift 2 ;;
    --version) [ "$#" -ge 2 ] || usage; version=$2; shift 2 ;;
    --sha256|--expected-sha256) [ "$#" -ge 2 ] || usage; expected_sha256=$2; shift 2 ;;
    --prefix) [ "$#" -ge 2 ] || usage; prefix=$2; shift 2 ;;
    --state-dir) [ "$#" -ge 2 ] || usage; state_dir=$2; shift 2 ;;
    --unit-dir) [ "$#" -ge 2 ] || usage; unit_dir=$2; shift 2 ;;
    --user) [ "$#" -ge 2 ] || usage; service_user=$2; shift 2 ;;
    --group) [ "$#" -ge 2 ] || usage; service_group=$2; shift 2 ;;
    --enable) enable=1; shift ;;
    --start) start=1; shift ;;
    --restart) restart=1; start=1; shift ;;
    --replace-unit) replace_unit=1; shift ;;
    --help|-h) usage ;;
    *) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die 'run as root to install a system service'
[ -n "$binary" ] || usage
[ -n "$version" ] || usage
[ -n "$expected_sha256" ] || usage
[ -n "$service_user" ] || die 'service user is required'
[ -n "$service_group" ] || die 'service group is required'
[ -f "$binary" ] && [ ! -L "$binary" ] && [ -x "$binary" ] || die 'binary must be an executable regular file'
case "$version" in *[!A-Za-z0-9._+-]*) die 'version contains unsafe characters' ;; esac
[ "$version" != "dev" ] || die 'version must be a release value'
case "$expected_sha256" in *[!0-9a-f]*) die 'sha256 must be 64 lowercase hexadecimal characters' ;; esac
[ "${#expected_sha256}" -eq 64 ] || die 'sha256 must be 64 lowercase hexadecimal characters'
command -v sha256sum >/dev/null 2>&1 || die 'sha256sum is required to verify release bytes'
for path in "$prefix" "$state_dir" "$unit_dir"; do
  case "$path" in
    /*) ;;
    *) die 'prefix, state-dir and unit-dir must be absolute paths' ;;
  esac
  case "$path" in *[!A-Za-z0-9._/+:-]*) die 'install paths contain unsafe characters' ;; esac
done
case "$service_user" in [A-Za-z0-9_]*);;*) die 'service user contains unsafe characters' ;; esac
case "$service_group" in [A-Za-z0-9_]*);;*) die 'service group contains unsafe characters' ;; esac
case "$service_user" in *[!A-Za-z0-9._-]*) die 'service user contains unsafe characters' ;; esac
case "$service_group" in *[!A-Za-z0-9._-]*) die 'service group contains unsafe characters' ;; esac

staging_dir=$(mktemp -d /tmp/opr-worker-install.XXXXXX) || die 'cannot create private staging directory'
trap 'rm -rf -- "$staging_dir"' EXIT HUP INT TERM
staged_binary=$staging_dir/opr-worker
install -o root -g root -m 0755 "$binary" "$staged_binary" || die 'cannot stage binary'
actual_sha256=$(sha256sum "$staged_binary") || die 'cannot hash staged binary'
actual_sha256=${actual_sha256%% *}
[ "$actual_sha256" = "$expected_sha256" ] || die 'binary SHA256 does not match trusted release digest'

# Verify version only after digest verification. The staged copy is immutable
# for this invocation, so a changing source path cannot alter what is checked.
reported=$("$staged_binary" version 2>/dev/null || true)
[ "$reported" = "$version" ] || die "binary reports version '$reported', expected '$version'"

if ! getent group "$service_group" >/dev/null 2>&1; then
  groupadd --system "$service_group"
fi
if ! getent passwd "$service_user" >/dev/null 2>&1; then
  useradd --system --gid "$service_group" --home-dir "$state_dir" --create-home --shell /usr/bin/nologin "$service_user"
else
  [ "$(id -gn "$service_user")" = "$service_group" ] || die "service user has a different primary group"
fi

release_dir=$prefix/lib/opr-worker/releases
launcher=$prefix/bin/opr-worker
release=$release_dir/opr-worker-$version
install -d -o root -g root -m 0755 "$release_dir" "$prefix/bin"
if [ -e "$release" ] || [ -L "$release" ]; then
  [ ! -L "$release" ] && [ -f "$release" ] && cmp -s "$staged_binary" "$release" || die "release $version already exists with different bytes"
else
  install -o root -g root -m 0755 "$staged_binary" "$release"
fi
if [ -e "$launcher" ] && [ ! -L "$launcher" ]; then
  die "$launcher is a regular file; refusing to replace it"
fi
link_tmp=$prefix/bin/.opr-worker-link.$$
trap 'rm -f "$link_tmp"; rm -rf -- "$staging_dir"' EXIT HUP INT TERM
ln -s ../lib/opr-worker/releases/opr-worker-$version "$link_tmp"
mv -f "$link_tmp" "$launcher"
trap 'rm -rf -- "$staging_dir"' EXIT HUP INT TERM

install -d -o "$service_user" -g "$service_group" -m 0700 "$state_dir"

install -d -o root -g root -m 0755 "$unit_dir"
unit_tmp=$unit_dir/.opr-worker.service.$$
trap 'rm -f "$unit_tmp"; rm -rf -- "$staging_dir"' EXIT HUP INT TERM
cat >"$unit_tmp" <<EOF
[Unit]
Description=OPR Arch package build worker
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$service_user
Group=$service_group
WorkingDirectory=$state_dir
Environment=HOME=$state_dir
Environment=XDG_RUNTIME_DIR=/run/opr-worker
Environment=PATH=$prefix/bin:/usr/bin:/bin
ExecStart=$launcher run --config $state_dir/config.json
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
UMask=0077
NoNewPrivileges=true
Delegate=yes
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$state_dir
RuntimeDirectory=opr-worker
RuntimeDirectoryMode=0700
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF
unit_path=$unit_dir/opr-worker.service
if [ -e "$unit_path" ] && ! cmp -s "$unit_tmp" "$unit_path" && [ "$replace_unit" -ne 1 ]; then
  die "$unit_path differs; pass --replace-unit to update it"
fi
install -o root -g root -m 0644 "$unit_tmp" "$unit_path"
rm -f "$unit_tmp"
trap 'rm -rf -- "$staging_dir"' EXIT HUP INT TERM

if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$unit_path" || die 'systemd unit validation failed'
fi

if [ "$enable" -eq 1 ] || [ "$start" -eq 1 ] || [ "$restart" -eq 1 ]; then
  [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 || die 'systemd is unavailable for requested service action'
  systemctl daemon-reload
  [ "$enable" -eq 1 ] && systemctl enable opr-worker.service
  if [ "$restart" -eq 1 ]; then
    systemctl restart opr-worker.service
  elif [ "$start" -eq 1 ]; then
    systemctl start opr-worker.service
  fi
elif [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet opr-worker.service; then
  printf '%s\n' 'service is active; installed release will run after an explicit systemctl restart opr-worker.service' >&2
fi

rm -rf -- "$staging_dir"
trap - EXIT HUP INT TERM
printf 'installed opr-worker %s at %s\n' "$version" "$release"
