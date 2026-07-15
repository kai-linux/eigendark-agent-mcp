#!/bin/bash
set -euo pipefail

ROOT=/home/bitnami/eigendark-agent-mcp
PYTHON=/home/bitnami/eigendark/runtime/bin/python
OPENAI_CA_DIR=/etc/nginx/openai-connectors

cd "$ROOT"
test -x "$PYTHON"

rm -rf .venv.next
"$PYTHON" -m venv .venv.next
.venv.next/bin/python -m pip install --disable-pip-version-check \
    --only-binary=:all: --require-hashes -r requirements-runtime.lock
.venv.next/bin/python -m pip install --disable-pip-version-check \
    --only-binary=:all: --require-hashes -r requirements-build.lock
.venv.next/bin/python -m pip install --disable-pip-version-check \
    --no-deps --no-build-isolation .

rm -rf .venv.previous
if test -d .venv; then mv .venv .venv.previous; fi
mv .venv.next .venv

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
curl --fail --silent --show-error --location \
    https://developers.openai.com/apps-sdk/mtls/openai-root-ca.pem \
    --output "$tmpdir/openai-root-ca.pem"
curl --fail --silent --show-error --location \
    https://developers.openai.com/apps-sdk/mtls/openai-connectors-mtls-ca.pem \
    --output "$tmpdir/openai-connectors-mtls-ca.pem"
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

sudo install -d -m 0755 "$OPENAI_CA_DIR"
sudo install -m 0644 "$tmpdir/client-ca.pem" "$OPENAI_CA_DIR/client-ca.pem"
sudo install -m 0644 deploy/eigendark-agent-mcp.service \
    /etc/systemd/system/eigendark-agent-mcp.service
sudo install -m 0644 deploy/api.eigendark.nginx.conf \
    /etc/nginx/sites-available/api.eigendark

sudo systemctl daemon-reload
sudo systemctl enable --now eigendark-agent-mcp.service

for attempt in {1..30}; do
    if curl --fail --silent --show-error http://127.0.0.1:5003/healthz >/dev/null; then
        break
    fi
    if test "$attempt" -eq 30; then
        sudo systemctl status --no-pager eigendark-agent-mcp.service
        exit 1
    fi
    sleep 1
done

sudo nginx -t
sudo systemctl reload nginx
trap - EXIT
rm -rf "$tmpdir"
echo "Eigendark ChatGPT MCP deployment complete"
