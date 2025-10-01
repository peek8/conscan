#!/bin/bash

TRIVY_VERSION="0.66.0"
GRYPE_VERSION="0.100.0"
SYFT_VERSION="1.33.0"
DIVE_VERSION="0.13.1"
DOCKLE_VERSION="0.4.15"


# Download other tools
echo "Installing Trivy of version ${TRIVY_VERSION}"
wget -qO-  https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

echo "Installing Grype of version ${GRYPE_VERSION}"
wget -qO- https://get.anchore.io/grype | sh -s -- -b /usr/local/bin v${GRYPE_VERSION}

echo "Installing Syft of version ${SYFT_VERSION}"
wget -qO- https://get.anchore.io/syft | sh -s -- -b /usr/local/bin v${SYFT_VERSION}


cat /dev/null <<EOF
------------------------------------------------------------------------
https://github.com/client9/shlib - portable posix shell functions
Public domain - http://unlicense.org
https://github.com/client9/shlib/blob/master/LICENSE.md
but credit (and pull requests) appreciated.
------------------------------------------------------------------------
EOF
is_command() {
  command -v "$1" >/dev/null
}
echoerr() {
  echo "$@" 1>&2
}
log_prefix() {
  echo "$0"
}
_logp=6
log_set_priority() {
  _logp="$1"
}
log_priority() {
  if test -z "$1"; then
    echo "$_logp"
    return
  fi
  [ "$1" -le "$_logp" ]
}
log_tag() {
  case $1 in
    0) echo "emerg" ;;
    1) echo "alert" ;;
    2) echo "crit" ;;
    3) echo "err" ;;
    4) echo "warning" ;;
    5) echo "notice" ;;
    6) echo "info" ;;
    7) echo "debug" ;;
    *) echo "$1" ;;
  esac
}
log_debug() {
  log_priority 7 || return 0
  echo "$(log_prefix)" "$(log_tag 7)" "$@"
}
log_info() {
  log_priority 6 || return 0
  echo "$(log_prefix)" "$(log_tag 6)" "$@"
}
log_err() {
  log_priority 3 || return 0
  echoerr "$(log_prefix)" "$(log_tag 3)" "$@"
}
log_crit() {
  log_priority 2 || return 0
  echoerr "$(log_prefix)" "$(log_tag 2)" "$@"
}
uname_os() {
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in
    cygwin_nt*) os="windows" ;;
    mingw*) os="windows" ;;
    msys_nt*) os="windows" ;;
  esac
  echo "$os"
}
uname_arch() {
  arch=$(uname -m)
  case $arch in
    x86_64) arch="amd64" ;;
    x86) arch="386" ;;
    i686) arch="386" ;;
    i386) arch="386" ;;
    ppc64le) arch="ppc64le" ;;
    aarch64) arch="arm64" ;;
    armv5*) arch="armv5" ;;
    armv6*) arch="armv6" ;;
    armv7*) arch="armv7" ;;
    s390*) arch="s390x" ;;
  esac
  echo ${arch}
}
uname_os_check() {
  os=$(uname_os)
  case "$os" in
    darwin) return 0 ;;
    dragonfly) return 0 ;;
    freebsd) return 0 ;;
    linux) return 0 ;;
    android) return 0 ;;
    nacl) return 0 ;;
    netbsd) return 0 ;;
    openbsd) return 0 ;;
    plan9) return 0 ;;
    solaris) return 0 ;;
    windows) return 0 ;;
  esac
  log_crit "uname_os_check '$(uname -s)' got converted to '$os' which is not a GOOS value. Please file bug at https://github.com/client9/shlib"
  return 1
}
uname_arch_check() {
  arch=$(uname_arch)
  case "$arch" in
    386) return 0 ;;
    amd64) return 0 ;;
    arm64) return 0 ;;
    armv5) return 0 ;;
    armv6) return 0 ;;
    armv7) return 0 ;;
    ppc64) return 0 ;;
    ppc64le) return 0 ;;
    mips) return 0 ;;
    mipsle) return 0 ;;
    mips64) return 0 ;;
    mips64le) return 0 ;;
    s390x) return 0 ;;
    amd64p32) return 0 ;;
  esac
  log_crit "uname_arch_check '$(uname -m)' got converted to '$arch' which is not a GOARCH value.  Please file bug report at https://github.com/client9/shlib"
  return 1
}
cat /dev/null <<EOF
------------------------------------------------------------------------
End of functions from https://github.com/client9/shlib
------------------------------------------------------------------------
EOF

# Dive download
OS=$(uname_os)
ARCH=$(uname_arch)
PLATFORM="${OS}_${ARCH}"

uname_os_check "$OS"
uname_arch_check "$ARCH"

dive_url="https://github.com/wagoodman/dive/releases/download/v${DIVE_VERSION}/dive_${DIVE_VERSION}_${PLATFORM}.tar.gz"

echo "Downloading Dive-${DIVE_VERSION} from ${dive_url}"

wget -qO-  ${dive_url} | tar -xz -C /usr/local/bin dive


# Dockle download
dockle_uname_os() {
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in
    cygwin_nt*) os="windows" ;;
    mingw*) os="windows" ;;
    msys_nt*) os="windows" ;;
    linux*) os="Linux" ;;
    darwin*) os="macOS" ;;
  esac
  echo "$os"
}

dockle_uname_arch() {
  arch=$(uname -m | tr '[:upper:]' '[:lower:]')
  case $arch in
    x86_64) arch="64bit" ;;
    amd64) arch="64bit" ;;
    x86) arch="386" ;;
    i686) arch="386" ;;
    i386) arch="386" ;;
    arm64) arch="ARM64" ;;
    aarch64) arch="ARM64" ;;
    arm) arch="ARM" ;;
    loong64) arch="LOONG64" ;;
  esac
  echo ${arch}
}

dockle_plaform_check() {
  platform=$1  
  case "$platform" in
    Linux-386) return 0 ;;
    Linux-64bit) return 0 ;;
    Linux-ARM) return 0 ;;
    Linux-ARM64) return 0 ;;
    Linux-LOONG64) return 0 ;;
    macOS-64bit) return 0 ;;
    macOS-ARM64) return 0 ;;
  esac
  echo "platform ${platform} not supported for dockle. Please have a look at the download page https://github.com/goodwithtech/dockle/releases"
  return 1
}


OS=$(dockle_uname_os)
ARCH=$(dockle_uname_arch)

PLATFORM="${OS}-${ARCH}"
dockle_plaform_check $PLATFORM

DOCKLE_DIST="dockle_${DOCKLE_VERSION}_${PLATFORM}.tar.gz"
dockle_url="https://github.com/goodwithtech/dockle/releases/download/v${DOCKLE_VERSION}/${DOCKLE_DIST}"

echo "Downloading Dockle-${DOCKLE_VERSION} from ${dockle_url}"

wget -qO- $dockle_url | tar -xz -C /usr/local/bin dockle