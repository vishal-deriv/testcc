#!/usr/bin/env bash
# fix-siem-config.sh — Fix SIEM auth: move from ?key= query param to x-api-key header
# Run with: sudo bash setup/fix-siem-config.sh
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root: sudo bash $0" >&2
    exit 1
fi

YAML="/etc/safeskill/agent.yaml"

if [[ ! -f "$YAML" ]]; then
    echo "ERROR: $YAML not found" >&2
    exit 1
fi

# Extract current siem_endpoint_url
current_url=$(grep 'siem_endpoint_url' "$YAML" | sed "s/.*siem_endpoint_url: *//")

# Extract API key from ?key= query param if present
api_key=""
if echo "$current_url" | grep -q '?key='; then
    api_key=$(echo "$current_url" | sed 's/.*?key=//')
    clean_url=$(echo "$current_url" | sed 's/?key=.*//')
    echo "[INFO] Extracted API key from query param"
elif grep -q 'siem_auth_header:' "$YAML"; then
    api_key=$(grep 'siem_auth_header:' "$YAML" | sed "s/.*siem_auth_header: *//")
    clean_url="$current_url"
    echo "[INFO] Using existing siem_auth_header value"
else
    echo "ERROR: Could not find API key in config. Please set manually." >&2
    echo "       Add to $YAML:" >&2
    echo "         siem_auth_header_name: x-api-key" >&2
    echo "         siem_auth_header: <YOUR_API_KEY>" >&2
    exit 1
fi

# Remove any trailing whitespace/newline from key
api_key=$(echo "$api_key" | tr -d '[:space:]')
clean_url=$(echo "$clean_url" | tr -d '[:space:]')

echo "[INFO] Clean URL: $clean_url"
echo "[INFO] API key:   ${api_key:0:8}... (truncated)"

# Rewrite the relevant lines in agent.yaml
# Remove old siem lines first, then re-add cleanly
python3 - "$YAML" "$clean_url" "$api_key" <<'PYEOF'
import sys, re

yaml_path = sys.argv[1]
clean_url = sys.argv[2]
api_key   = sys.argv[3]

with open(yaml_path, 'r') as f:
    content = f.read()

# Remove existing siem_* lines
content = re.sub(r'^siem_endpoint_url:.*\n?', '', content, flags=re.MULTILINE)
content = re.sub(r'^siem_auth_header:.*\n?', '', content, flags=re.MULTILINE)
content = re.sub(r'^siem_auth_header_name:.*\n?', '', content, flags=re.MULTILINE)

# Ensure trailing newline
content = content.rstrip('\n') + '\n'

# Append clean SIEM config
content += f"siem_endpoint_url: {clean_url}\n"
content += f"siem_auth_header_name: x-api-key\n"
content += f"siem_auth_header: {api_key}\n"

with open(yaml_path, 'w') as f:
    f.write(content)

print("[OK] agent.yaml updated")
PYEOF

echo ""
echo "Current /etc/safeskill/agent.yaml:"
cat "$YAML"
echo ""
echo "Now restart the SafeSkillAgent daemon:"
echo "  sudo launchctl stop com.safeskill.agent && sleep 2 && sudo launchctl start com.safeskill.agent"
