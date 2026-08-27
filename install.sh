#!/bin/sh

set -eu

repository="v3dillon/ecco"
install_dir=${ECCO_INSTALL_DIR:-"${HOME:?HOME is not set}/.local/bin"}
version=${ECCO_VERSION:-latest}

fail() {
  printf 'ecco installer: %s\n' "$1" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

case "$(uname -s)" in
  Darwin) operating_system="apple-darwin" ;;
  Linux) operating_system="unknown-linux-musl" ;;
  *) fail "unsupported operating system: $(uname -s)" ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) architecture="x86_64" ;;
  arm64 | aarch64) architecture="aarch64" ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

target="${architecture}-${operating_system}"
archive="ecco-${target}.tar.gz"
releases_url="https://github.com/${repository}/releases"

if [ "$version" = "latest" ]; then
  download_url="${releases_url}/latest/download"
else
  case "$version" in
    v*) ;;
    *) version="v${version}" ;;
  esac
  download_url="${releases_url}/download/${version}"
fi

temporary_dir=$(mktemp -d 2>/dev/null || mktemp -d -t ecco)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

printf 'Downloading ecco for %s...\n' "$target"
curl --proto '=https' --tlsv1.2 -fsSL \
  "${download_url}/${archive}" -o "${temporary_dir}/${archive}"
curl --proto '=https' --tlsv1.2 -fsSL \
  "${download_url}/${archive}.sha256" -o "${temporary_dir}/${archive}.sha256"

expected_checksum=$(sed 's/[[:space:]].*$//' "${temporary_dir}/${archive}.sha256")
if command -v sha256sum >/dev/null 2>&1; then
  actual_checksum=$(sha256sum "${temporary_dir}/${archive}" | sed 's/[[:space:]].*$//')
elif command -v shasum >/dev/null 2>&1; then
  actual_checksum=$(shasum -a 256 "${temporary_dir}/${archive}" | sed 's/[[:space:]].*$//')
else
  fail "sha256sum or shasum is required"
fi

[ "$expected_checksum" = "$actual_checksum" ] || fail "checksum verification failed"

tar -xzf "${temporary_dir}/${archive}" -C "$temporary_dir"
[ -f "${temporary_dir}/ecco" ] || fail "the release archive does not contain ecco"

mkdir -p "$install_dir"
install -m 755 "${temporary_dir}/ecco" "${install_dir}/ecco"

printf 'Installed ecco to %s/ecco\n' "$install_dir"
case ":${PATH}:" in
  *:"${install_dir}":*) ;;
  *)
    printf 'Add %s to PATH before you run ecco:\n' "$install_dir"
    printf '  export PATH="%s:$PATH"\n' "$install_dir"
    ;;
esac
