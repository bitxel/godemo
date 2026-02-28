#!/usr/bin/env bash
# godemo installer — one-liner install for godemo-cli and/or godemo-gateway
#
#   curl -fsSL https://raw.githubusercontent.com/bitxel/godemo/main/install.sh | bash
#   curl -fsSL ... | bash -s -- --component gateway --install-dir /opt/godemo
#
# Flags:
#   --component cli|gateway|all   Which binary to install (default: cli)
#   --install-dir <dir>           Install directory (default: ~/.local/bin)
#   --version <tag>               Specific release tag (default: latest)
#   --dry-run                     Print actions without applying
#   --verbose                     Enable debug output
#   --help                        Show usage
#
# Environment variables (override flags):
#   GODEMO_INSTALL_COMPONENT   cli|gateway|all
#   GODEMO_INSTALL_DIR         Install directory
#   GODEMO_INSTALL_VERSION     Release tag (e.g. v0.3.0)
#   GODEMO_INSTALL_DRY_RUN     1 to enable
#   GODEMO_INSTALL_VERBOSE     1 to enable
#
# shellcheck disable=SC2059

set -euo pipefail

REPO_OWNER="bitxel"
REPO_NAME="godemo"
API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases"
INSTALL_PREFIX="${GODEMO_INSTALL_DIR:-${HOME}/.local/bin}"
COMPONENT="${GODEMO_INSTALL_COMPONENT:-cli}"
VERSION="${GODEMO_INSTALL_VERSION:-latest}"
DRY_RUN="${GODEMO_INSTALL_DRY_RUN:-0}"
VERBOSE="${GODEMO_INSTALL_VERBOSE:-0}"

# ── colours (disabled when not a terminal) ───────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

# ── logging ──────────────────────────────────────────────────────────
info()    { printf "${BLUE}info${NC}  %s\n"    "$*"; }
ok()      { printf "${GREEN}  ok${NC}  %s\n"    "$*"; }
warn()    { printf "${YELLOW}warn${NC}  %s\n"   "$*" >&2; }
err()     { printf "${RED} err${NC}  %s\n"      "$*" >&2; }
debug()   { [ "$VERBOSE" = "1" ] && printf "${CYAN} dbg${NC}  %s\n" "$*" || true; }

die() { err "$@"; exit 1; }

# ── usage ────────────────────────────────────────────────────────────
usage() {
  cat <<'HELP'
godemo installer

Usage:
  curl -fsSL https://raw.githubusercontent.com/bitxel/godemo/main/install.sh | bash
  curl -fsSL ... | bash -s -- [OPTIONS]

Options:
  --component <cli|gateway|all>   Binary to install (default: cli)
  --install-dir <dir>             Install directory (default: ~/.local/bin)
  --version <tag>                 Release tag e.g. v0.3.0 (default: latest)
  --dry-run                       Print actions, don't execute
  --verbose                       Debug output
  -h, --help                      Show this message

Examples:
  # Install godemo-cli (default)
  curl -fsSL ... | bash

  # Install both CLI and gateway
  curl -fsSL ... | bash -s -- --component all

  # Install gateway to /opt/godemo with specific version
  curl -fsSL ... | bash -s -- --component gateway --install-dir /opt/godemo --version v0.3.0
HELP
}

# ── argument parsing ─────────────────────────────────────────────────
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --component)    shift; COMPONENT="${1:?'--component requires a value'}" ;;
      --install-dir)  shift; INSTALL_PREFIX="${1:?'--install-dir requires a value'}" ;;
      --version)      shift; VERSION="${1:?'--version requires a value'}" ;;
      --dry-run)      DRY_RUN=1 ;;
      --verbose)      VERBOSE=1 ;;
      -h|--help)      usage; exit 0 ;;
      *)              die "unknown option: $1 (try --help)" ;;
    esac
    shift
  done

  case "$COMPONENT" in
    cli|gateway|all) ;;
    *) die "invalid --component '$COMPONENT' (must be cli, gateway, or all)" ;;
  esac
}

# ── platform detection ───────────────────────────────────────────────
detect_platform() {
  local os arch

  case "$(uname -s)" in
    Linux*)   os="linux"   ;;
    Darwin*)  os="darwin"  ;;
    MINGW*|MSYS*|CYGWIN*) os="windows" ;;
    *)        die "unsupported OS: $(uname -s)" ;;
  esac

  case "$(uname -m)" in
    x86_64|amd64)   arch="amd64"  ;;
    arm64|aarch64)  arch="arm64"  ;;
    *)              die "unsupported architecture: $(uname -m)" ;;
  esac

  PLATFORM_OS="$os"
  PLATFORM_ARCH="$arch"

  debug "detected platform: ${os}/${arch}"
}

# ── dependency checks ────────────────────────────────────────────────
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1 — please install it first"
}

check_deps() {
  if command -v curl >/dev/null 2>&1; then
    FETCH="curl"
  elif command -v wget >/dev/null 2>&1; then
    FETCH="wget"
  else
    die "either curl or wget is required"
  fi
  debug "using $FETCH for downloads"
}

# ── HTTP helpers ─────────────────────────────────────────────────────
fetch_url() {
  local url="$1"
  if [ "$FETCH" = "curl" ]; then
    curl -fsSL --proto '=https' --tlsv1.2 "$url"
  else
    wget -qO- "$url"
  fi
}

download_file() {
  local url="$1" dest="$2"
  info "downloading $(basename "$dest")…"
  debug "  url: $url"

  if [ "$DRY_RUN" = "1" ]; then
    ok "[dry-run] would download → $dest"
    return
  fi

  if [ "$FETCH" = "curl" ]; then
    curl -fSL --proto '=https' --tlsv1.2 -o "$dest" "$url"
  else
    wget -q -O "$dest" "$url"
  fi
}

# ── GitHub release resolution ────────────────────────────────────────
resolve_version() {
  if [ "$VERSION" = "latest" ]; then
    info "resolving latest release…"
    local api_resp
    api_resp="$(fetch_url "${API_URL}/latest")"
    VERSION="$(printf '%s' "$api_resp" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    [ -n "$VERSION" ] || die "could not determine latest release (GitHub API rate limit?)"
    ok "latest release: ${BOLD}${VERSION}${NC}"
  else
    info "using requested version: ${BOLD}${VERSION}${NC}"
  fi
}

# Construct the download URL for a given binary name.
# Release assets follow: godemo-cli-linux-amd64, godemo-gateway-darwin-arm64
# Older releases used godemo-client instead of godemo-cli.
asset_url() {
  local binary="$1"
  local ext=""
  [ "$PLATFORM_OS" = "windows" ] && ext=".exe"
  printf "https://github.com/%s/%s/releases/download/%s/%s-%s-%s%s" \
    "$REPO_OWNER" "$REPO_NAME" "$VERSION" "$binary" "$PLATFORM_OS" "$PLATFORM_ARCH" "$ext"
}

# Check whether a URL exists (HTTP 200) without downloading the body.
url_exists() {
  if [ "$FETCH" = "curl" ]; then
    curl -fsSL --proto '=https' --tlsv1.2 -o /dev/null -w '%{http_code}' --head "$1" 2>/dev/null | grep -q 200
  else
    wget --spider -q "$1" 2>/dev/null
  fi
}

# ── installation ─────────────────────────────────────────────────────
install_binary() {
  local name="$1"
  local url dest ext=""

  [ "$PLATFORM_OS" = "windows" ] && ext=".exe"
  url="$(asset_url "$name")"

  # Older releases named the CLI binary "godemo-client"; fall back if needed.
  if [ "$name" = "godemo-cli" ] && ! url_exists "$url"; then
    local legacy_url
    legacy_url="$(asset_url "godemo-client")"
    if url_exists "$legacy_url"; then
      debug "asset $name not found; falling back to godemo-client"
      url="$legacy_url"
    fi
  fi

  dest="${INSTALL_PREFIX}/${name}${ext}"

  if [ "$DRY_RUN" = "1" ]; then
    ok "[dry-run] would install ${BOLD}${name}${NC} → $dest"
    return
  fi

  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT

  download_file "$url" "$tmp"
  chmod +x "$tmp"

  mkdir -p "$INSTALL_PREFIX"
  mv "$tmp" "$dest"
  trap - EXIT

  ok "installed ${BOLD}${name}${NC} → $dest"
}

# ── PATH advisory ────────────────────────────────────────────────────
check_path() {
  case ":$PATH:" in
    *":${INSTALL_PREFIX}:"*) return ;;
  esac

  echo ""
  warn "${BOLD}${INSTALL_PREFIX}${NC} is not in your \$PATH"
  echo ""
  printf "  Add it by appending one of the following to your shell profile:\n\n"

  local shell_name
  shell_name="$(basename "${SHELL:-/bin/sh}")"
  case "$shell_name" in
    zsh)
      printf "    ${CYAN}echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc && source ~/.zshrc${NC}\n" "$INSTALL_PREFIX"
      ;;
    bash)
      printf "    ${CYAN}echo 'export PATH=\"%s:\$PATH\"' >> ~/.bashrc && source ~/.bashrc${NC}\n" "$INSTALL_PREFIX"
      ;;
    fish)
      printf "    ${CYAN}fish_add_path %s${NC}\n" "$INSTALL_PREFIX"
      ;;
    *)
      printf "    ${CYAN}export PATH=\"%s:\$PATH\"${NC}\n" "$INSTALL_PREFIX"
      ;;
  esac
  echo ""
}

# ── post-install summary ─────────────────────────────────────────────
print_summary() {
  local components=()
  case "$COMPONENT" in
    cli)     components=("godemo-cli") ;;
    gateway) components=("godemo-gateway") ;;
    all)     components=("godemo-cli" "godemo-gateway") ;;
  esac

  echo ""
  printf "  ${GREEN}${BOLD}godemo ${VERSION} installed successfully${NC}\n"
  echo ""

  for c in "${components[@]}"; do
    local p="${INSTALL_PREFIX}/${c}"
    [ "$PLATFORM_OS" = "windows" ] && p="${p}.exe"
    printf "  %-20s %s\n" "$c" "$p"
  done

  echo ""

  # quick-start hints
  if [[ " ${components[*]} " == *" godemo-cli "* ]]; then
    printf "  ${BOLD}Quick start:${NC}\n\n"
    printf "    ${CYAN}godemo-cli 3000${NC}          # expose local port 3000\n"
    printf "    ${CYAN}godemo-cli 8080 -v${NC}       # verbose mode\n"
    echo ""
  fi

  if [[ " ${components[*]} " == *" godemo-gateway "* ]]; then
    printf "  ${BOLD}Gateway:${NC}\n\n"
    printf "    ${CYAN}GODEMO_ROOT_DOMAIN=tunnel.example.com godemo-gateway${NC}\n"
    printf "    See ${CYAN}https://github.com/bitxel/godemo/blob/main/docs/gateway_deployment.md${NC}\n"
    echo ""
  fi

  printf "  ${BOLD}Docs:${NC}      https://github.com/${REPO_OWNER}/${REPO_NAME}#readme\n"
  printf "  ${BOLD}Releases:${NC}  https://github.com/${REPO_OWNER}/${REPO_NAME}/releases\n"
  echo ""
}

# ── verify installation ──────────────────────────────────────────────
verify() {
  if [ "$DRY_RUN" = "1" ]; then return; fi

  local components=()
  case "$COMPONENT" in
    cli)     components=("godemo-cli") ;;
    gateway) components=("godemo-gateway") ;;
    all)     components=("godemo-cli" "godemo-gateway") ;;
  esac

  for c in "${components[@]}"; do
    local p="${INSTALL_PREFIX}/${c}"
    [ "$PLATFORM_OS" = "windows" ] && p="${p}.exe"
    if [ ! -x "$p" ]; then
      die "verification failed: $p is not executable"
    fi
    debug "verified $p exists and is executable"
  done
}

# ── main ─────────────────────────────────────────────────────────────
main() {
  parse_args "$@"

  echo ""
  printf "  ${BOLD}godemo installer${NC}\n"
  echo ""

  detect_platform
  check_deps
  resolve_version

  case "$COMPONENT" in
    cli)
      install_binary "godemo-cli"
      ;;
    gateway)
      install_binary "godemo-gateway"
      ;;
    all)
      install_binary "godemo-cli"
      install_binary "godemo-gateway"
      ;;
  esac

  verify
  check_path
  print_summary
}

main "$@"
