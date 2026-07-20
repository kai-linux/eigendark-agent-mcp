#!/bin/bash
set -euo pipefail

ROOT=/home/bitnami/eigendark-agent-mcp
SOURCE_PYTHON=/home/bitnami/eigendark/runtime/bin/python
RUNTIME=/opt/eigendark-agent-mcp
RUNTIME_NEXT=/opt/eigendark-agent-mcp.next
RUNTIME_PREVIOUS=/opt/eigendark-agent-mcp.previous
PYTHON_INSTALL_ROOT=/opt/eigendark-python
OPENAI_CA_DIR=/etc/nginx/openai-connectors
OPENAI_ACTIONS_IP_DIR=/etc/nginx/openai-actions

cd "$ROOT"
test -x "$SOURCE_PYTHON"

source_python_real=$(readlink -f "$SOURCE_PYTHON")
source_python_root=$(dirname "$(dirname "$source_python_real")")
python_id=$(basename "$source_python_root")-$(sha256sum "$source_python_real" | cut -c1-16)
python_root="$PYTHON_INSTALL_ROOT/$python_id"
python="$python_root/bin/python3.12"

if ! test -x "$python"; then
    sudo install -d -m 0755 "$PYTHON_INSTALL_ROOT"
    sudo rm -rf "$python_root.next"
    sudo cp -a "$source_python_root" "$python_root.next"
    sudo chown -R root:root "$python_root.next"
    sudo chmod -R go-w "$python_root.next"
    sudo mv "$python_root.next" "$python_root"
fi
test -x "$python"

sudo rm -rf "$RUNTIME_NEXT"
sudo install -d -m 0755 -o bitnami -g bitnami "$RUNTIME_NEXT"
"$python" -m venv "$RUNTIME_NEXT/.venv"
"$RUNTIME_NEXT/.venv/bin/python" -m pip install --disable-pip-version-check \
    --only-binary=:all: --require-hashes -r requirements-runtime.lock
"$RUNTIME_NEXT/.venv/bin/python" -m pip install --disable-pip-version-check \
    --only-binary=:all: --require-hashes -r requirements-build.lock
"$RUNTIME_NEXT/.venv/bin/python" -m pip install --disable-pip-version-check \
    --no-deps --no-build-isolation .
sudo chown -R root:root "$RUNTIME_NEXT"
sudo chmod -R go-w "$RUNTIME_NEXT"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
curl --fail --silent --show-error --location \
    https://developers.openai.com/apps-sdk/mtls/openai-root-ca.pem \
    --output "$tmpdir/openai-root-ca.pem"
curl --fail --silent --show-error --location \
    https://developers.openai.com/apps-sdk/mtls/openai-connectors-mtls-ca.pem \
    --output "$tmpdir/openai-connectors-mtls-ca.pem"
curl --fail --silent --show-error --location \
    https://openai.com/chatgpt-actions.json \
    --output "$tmpdir/chatgpt-actions.json"
openssl x509 -in "$tmpdir/openai-root-ca.pem" -noout >/dev/null
openssl x509 -in "$tmpdir/openai-connectors-mtls-ca.pem" -noout >/dev/null
test "$(openssl x509 -in "$tmpdir/openai-root-ca.pem" -noout -subject -nameopt RFC2253)" = \
    "subject=CN=OpenAI-Root-CA,O=OpenAI"
test "$(openssl x509 -in "$tmpdir/openai-root-ca.pem" -noout -issuer -nameopt RFC2253)" = \
    "issuer=CN=OpenAI-Root-CA,O=OpenAI"
test "$(openssl x509 -in "$tmpdir/openai-connectors-mtls-ca.pem" -noout -subject -nameopt RFC2253)" = \
    "subject=CN=OpenAI-Connectors-mTLS-CA,O=OpenAI"
test "$(openssl x509 -in "$tmpdir/openai-connectors-mtls-ca.pem" -noout -issuer -nameopt RFC2253)" = \
    "issuer=CN=OpenAI-Root-CA,O=OpenAI"
openssl verify -CAfile "$tmpdir/openai-root-ca.pem" \
    "$tmpdir/openai-connectors-mtls-ca.pem"
cat "$tmpdir/openai-connectors-mtls-ca.pem" "$tmpdir/openai-root-ca.pem" \
    > "$tmpdir/client-ca.pem"

"$python" - "$tmpdir/chatgpt-actions.json" "$tmpdir/client-ips.conf" <<'PY'
import ipaddress
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
document = json.loads(source.read_text(encoding="utf-8"))
prefixes = document.get("prefixes")
if not isinstance(prefixes, list) or not 32 <= len(prefixes) <= 1024:
    raise SystemExit("OpenAI Actions IP document had an unexpected shape")
networks = set()
for entry in prefixes:
    if not isinstance(entry, dict):
        raise SystemExit("OpenAI Actions IP entry was invalid")
    value = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError) as exc:
        raise SystemExit("OpenAI Actions IP prefix was invalid") from exc
    if not network.is_global:
        raise SystemExit("OpenAI Actions IP prefix was not public")
    networks.add(network)
ordered = sorted(networks, key=lambda item: (item.version, int(item.network_address), item.prefixlen))
destination.write_text("".join(f"    {item} 1;\n" for item in ordered), encoding="ascii")
PY

sudo install -d -m 0755 "$OPENAI_CA_DIR"
sudo install -m 0644 "$tmpdir/client-ca.pem" "$OPENAI_CA_DIR/client-ca.pem"
sudo install -d -m 0755 "$OPENAI_ACTIONS_IP_DIR"
sudo install -m 0644 "$tmpdir/client-ips.conf" "$OPENAI_ACTIONS_IP_DIR/client-ips.conf"
sudo install -m 0644 deploy/eigendark-agent-mcp.service \
    /etc/systemd/system/eigendark-agent-mcp.service
sudo install -m 0644 deploy/api.eigendark.nginx.conf \
    /etc/nginx/sites-available/api.eigendark

sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl enable eigendark-agent-mcp.service
sudo systemctl stop eigendark-agent-mcp.service || true
sudo rm -rf "$RUNTIME_PREVIOUS"
if test -d "$RUNTIME"; then sudo mv "$RUNTIME" "$RUNTIME_PREVIOUS"; fi
sudo mv "$RUNTIME_NEXT" "$RUNTIME"
sudo systemctl start eigendark-agent-mcp.service

healthy=0
for attempt in {1..30}; do
    if curl --fail --silent http://127.0.0.1:5003/healthz >/dev/null; then
        healthy=1
        break
    fi
    sleep 1
done
if test "$healthy" -ne 1; then
    sudo systemctl stop eigendark-agent-mcp.service || true
    if test -d "$RUNTIME_PREVIOUS"; then
        sudo rm -rf "$RUNTIME"
        sudo mv "$RUNTIME_PREVIOUS" "$RUNTIME"
        sudo systemctl start eigendark-agent-mcp.service || true
    fi
    sudo systemctl status --no-pager eigendark-agent-mcp.service || true
    exit 1
fi

sudo systemctl reload nginx
trap - EXIT
rm -rf "$tmpdir"
echo "Eigendark ChatGPT MCP deployment complete"
