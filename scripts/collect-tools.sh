#!/usr/bin/env bash
# collect-tools.sh — Download all tools from upstream, compute SHA256, create GitHub Release
#
# Usage:
#   ./scripts/collect-tools.sh                    # Download only
#   ./scripts/collect-tools.sh --release          # Download + create GitHub Release
#   ./scripts/collect-tools.sh --update-hashes    # Download + update tools.yaml with SHA256
#   ./scripts/collect-tools.sh --release --update-hashes  # All of the above
#
# Prerequisites:
#   - Python 3.9+ with pyyaml
#   - gh CLI (authenticated) for --release
#   - curl
#
# This script downloads every tool defined in server/catalog/tools.yaml from
# its upstream_url, stores it in staging/, computes SHA256 hashes, and
# optionally creates a GitHub Release with all files as assets.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CATALOG="$PROJECT_ROOT/server/catalog/tools.yaml"
STAGING="$PROJECT_ROOT/staging"
RELEASE_TAG="tools-v1.0.0"
REPO="Real-Fruit-Snacks/Seep"

DO_RELEASE=false
DO_UPDATE_HASHES=false
MAX_PARALLEL=4

for arg in "$@"; do
    case "$arg" in
        --release) DO_RELEASE=true ;;
        --update-hashes) DO_UPDATE_HASHES=true ;;
        --help|-h)
            head -14 "$0" | tail -13
            exit 0
            ;;
    esac
done

# Colors
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[~]${RESET} $*"; }
fail()  { echo -e "${RED}[!]${RESET} $*"; }

# --------------------------------------------------------------------------
# Parse catalog
# --------------------------------------------------------------------------

info "Parsing catalog: $CATALOG"

TOOL_DATA=$(python3 -c "
import yaml, json
with open('$CATALOG') as f:
    data = yaml.safe_load(f)
tools = data.get('tools', [])
for t in tools:
    print(json.dumps({'name': t['name'], 'upstream_url': t['upstream_url'], 'folder': t['folder']}))
")

TOTAL=$(echo "$TOOL_DATA" | wc -l)
info "Found ${BOLD}$TOTAL${RESET} tools to download"
echo

# --------------------------------------------------------------------------
# Download
# --------------------------------------------------------------------------

mkdir -p "$STAGING"
SUCCEEDED=0
FAILED=0
FAILED_NAMES=""

download_tool() {
    local name="$1"
    local url="$2"
    local dest="$STAGING/$name"

    if [[ -f "$dest" ]]; then
        return 0
    fi

    if curl -fsSL --connect-timeout 30 --max-time 300 -o "$dest.tmp" "$url" 2>/dev/null; then
        mv "$dest.tmp" "$dest"
        return 0
    else
        rm -f "$dest.tmp"
        return 1
    fi
}

export -f download_tool
export STAGING

COUNT=0
while IFS= read -r line; do
    NAME=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin)['name'])")
    URL=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin)['upstream_url'])")
    COUNT=$((COUNT + 1))

    if [[ -f "$STAGING/$NAME" ]]; then
        SIZE=$(stat -c%s "$STAGING/$NAME" 2>/dev/null || stat -f%z "$STAGING/$NAME" 2>/dev/null)
        KB=$((SIZE / 1024))
        echo -e "  ${DIM}[$COUNT/$TOTAL]${RESET} ${GREEN}cached${RESET}  $NAME (${KB} KB)"
        SUCCEEDED=$((SUCCEEDED + 1))
        continue
    fi

    if curl -fsSL --connect-timeout 30 --max-time 300 -o "$STAGING/$NAME.tmp" "$URL" 2>/dev/null; then
        mv "$STAGING/$NAME.tmp" "$STAGING/$NAME"
        SIZE=$(stat -c%s "$STAGING/$NAME" 2>/dev/null || stat -f%z "$STAGING/$NAME" 2>/dev/null)
        KB=$((SIZE / 1024))
        echo -e "  ${DIM}[$COUNT/$TOTAL]${RESET} ${GREEN}ok${RESET}      $NAME (${KB} KB)"
        SUCCEEDED=$((SUCCEEDED + 1))
    else
        rm -f "$STAGING/$NAME.tmp"
        echo -e "  ${DIM}[$COUNT/$TOTAL]${RESET} ${RED}FAIL${RESET}    $NAME"
        FAILED=$((FAILED + 1))
        FAILED_NAMES="$FAILED_NAMES $NAME"
    fi
done <<< "$TOOL_DATA"

echo
if [[ $FAILED -gt 0 ]]; then
    warn "$SUCCEEDED succeeded, $FAILED failed"
    fail "Failed tools:$FAILED_NAMES"
else
    ok "$SUCCEEDED succeeded, 0 failed"
fi

# --------------------------------------------------------------------------
# Compute SHA256 hashes
# --------------------------------------------------------------------------

echo
info "Computing SHA256 hashes..."

HASH_FILE="$STAGING/sha256sums.txt"
> "$HASH_FILE"

for f in "$STAGING"/*; do
    [[ -f "$f" ]] || continue
    [[ "$(basename "$f")" == "sha256sums.txt" ]] && continue
    HASH=$(sha256sum "$f" | awk '{print $1}')
    echo "$HASH  $(basename "$f")" >> "$HASH_FILE"
done

HASH_COUNT=$(wc -l < "$HASH_FILE")
ok "Computed $HASH_COUNT hashes → $HASH_FILE"

# --------------------------------------------------------------------------
# Update tools.yaml with SHA256 hashes
# --------------------------------------------------------------------------

if $DO_UPDATE_HASHES; then
    echo
    info "Updating tools.yaml with SHA256 hashes..."

    python3 -c "
import yaml

with open('$CATALOG') as f:
    data = yaml.safe_load(f)

# Build hash lookup from sha256sums.txt
hashes = {}
with open('$HASH_FILE') as f:
    for line in f:
        parts = line.strip().split('  ', 1)
        if len(parts) == 2:
            hashes[parts[1]] = parts[0]

updated = 0
for tool in data.get('tools', []):
    name = tool['name']
    if name in hashes and tool.get('sha256', '') != hashes[name]:
        tool['sha256'] = hashes[name]
        updated += 1

with open('$CATALOG', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=120)

print(f'  Updated {updated} SHA256 hashes in tools.yaml')
"

    ok "tools.yaml updated"
fi

# --------------------------------------------------------------------------
# Create GitHub Release
# --------------------------------------------------------------------------

if $DO_RELEASE; then
    echo
    info "Creating GitHub Release: ${BOLD}$RELEASE_TAG${RESET}"

    if ! command -v gh &>/dev/null; then
        fail "gh CLI not found. Install: https://cli.github.com/"
        exit 1
    fi

    # Check if release already exists
    if gh release view "$RELEASE_TAG" --repo "$REPO" &>/dev/null; then
        warn "Release $RELEASE_TAG already exists — uploading assets to existing release"
    else
        gh release create "$RELEASE_TAG" \
            --repo "$REPO" \
            --title "Tool Catalog $RELEASE_TAG" \
            --notes "Self-hosted tool binaries for seep catalog download.

Contains $HASH_COUNT tools across 7 categories (Enumeration, Credentials, TokenAbuse, AD, Tunneling, Impacket, Shells).

**Integrity:** Every tool has a SHA256 hash in \`tools.yaml\`. Verify with \`seep catalog verify\`.

**Usage:**
\`\`\`bash
seep catalog download --all --workdir /tmp/op1
seep catalog verify --workdir /tmp/op1
\`\`\`"
        ok "Release created"
    fi

    # Upload assets
    echo
    info "Uploading $HASH_COUNT assets (this may take a while)..."

    UPLOAD_OK=0
    UPLOAD_FAIL=0

    for f in "$STAGING"/*; do
        [[ -f "$f" ]] || continue
        BASENAME=$(basename "$f")
        [[ "$BASENAME" == "sha256sums.txt" ]] && continue

        if gh release upload "$RELEASE_TAG" "$f" --repo "$REPO" --clobber 2>/dev/null; then
            UPLOAD_OK=$((UPLOAD_OK + 1))
            echo -e "  ${GREEN}uploaded${RESET}  $BASENAME"
        else
            UPLOAD_FAIL=$((UPLOAD_FAIL + 1))
            echo -e "  ${RED}FAIL${RESET}      $BASENAME"
        fi
    done

    # Upload sha256sums.txt too
    gh release upload "$RELEASE_TAG" "$HASH_FILE" --repo "$REPO" --clobber 2>/dev/null && \
        echo -e "  ${GREEN}uploaded${RESET}  sha256sums.txt"

    echo
    if [[ $UPLOAD_FAIL -gt 0 ]]; then
        warn "$UPLOAD_OK uploaded, $UPLOAD_FAIL failed"
    else
        ok "$UPLOAD_OK assets uploaded to $RELEASE_TAG"
    fi

    echo
    ok "Release URL: https://github.com/$REPO/releases/tag/$RELEASE_TAG"
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------

echo
TOTAL_SIZE=$(du -sh "$STAGING" 2>/dev/null | awk '{print $1}')
echo -e "${BOLD}Summary${RESET}"
echo -e "  Tools downloaded : $SUCCEEDED / $TOTAL"
echo -e "  Staging dir      : $STAGING ($TOTAL_SIZE)"
echo -e "  SHA256 hashes    : $HASH_FILE"
if $DO_UPDATE_HASHES; then
    echo -e "  tools.yaml       : updated"
fi
if $DO_RELEASE; then
    echo -e "  GitHub Release   : https://github.com/$REPO/releases/tag/$RELEASE_TAG"
fi
echo
