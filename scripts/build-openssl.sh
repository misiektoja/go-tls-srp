#!/usr/bin/env bash
# Builds the OpenSSL 1.1.1 command line tool that TestOpenSSLServer runs against. The s_server of
# OpenSSL 3.0 and later cannot serve SRP, see "Tested servers" in the README.
#
# Usage: scripts/build-openssl.sh <prefix>
#
# The binary is installed as <prefix>/bin/openssl and reused while it reports the pinned version. The
# source and the build tree stay under <prefix>/build. CI caches the binary keyed on this file, so a
# change to the version or the build options here also replaces the cached binary.
set -euo pipefail

version=1.1.1w
sha256=cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8
url="https://github.com/openssl/openssl/releases/download/OpenSSL_${version//./_}/openssl-${version}.tar.gz"

if [ $# -ne 1 ] || [ -z "$1" ]; then
	echo "usage: $0 <prefix>" >&2
	exit 2
fi
mkdir -p "$1"
prefix="$(cd "$1" && pwd)"
binary="$prefix/bin/openssl"

if [ -x "$binary" ] && "$binary" version | grep -q "^OpenSSL $version "; then
	echo "using $("$binary" version) at $binary"
	exit 0
fi

build="$prefix/build"
tarball="$build/openssl-$version.tar.gz"
mkdir -p "$build"
if ! printf '%s  %s\n' "$sha256" "$tarball" | shasum -a 256 -c - >/dev/null 2>&1; then
	echo "downloading $url"
	curl -fsSL --retry 3 -o "$tarball" "$url"
	printf '%s  %s\n' "$sha256" "$tarball" | shasum -a 256 -c -
fi
tar -xzf "$tarball" -C "$build"

# A static binary needs only the C library, so a cached copy keeps working on the next runner.
# OpenSSL 1.1.1 builds SRP by default. Variables given to the calling make, such as VERSION, reach a
# nested make through MAKEFLAGS and would override the ones in OpenSSL's Makefile.
unset MAKEFLAGS MFLAGS MAKELEVEL
cd "$build/openssl-$version"
./config --prefix="$prefix" --openssldir="$prefix/ssl" no-shared no-tests
make -j"$(getconf _NPROCESSORS_ONLN)" build_programs
mkdir -p "$prefix/bin"
cp apps/openssl "$binary"
echo "built $("$binary" version) at $binary"
