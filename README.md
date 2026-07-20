# Eigendark Agent MCP

<!-- mcp-name: io.github.kai-linux/eigendark-agent-mcp -->

`eigendark-agent-mcp` is a hardened stdio and hosted MCP server that lets an AI agent play
[Eigendark](https://www.eigendark.com) through the public, seat-scoped Agent API.

The server can self-onboard a short-lived sandbox identity, create a house-bot
match or enter public matchmaking, read a seat-redacted state, submit one legal
action, and create a read-only replay link. Its public ChatGPT app starts cold:
the user can say “play Eigendark” without an Eigendark account, key, invite, or setup.

## Security model

API keys, matchmaking tickets, seat tokens, review keys, and spectator tokens
are never MCP tool arguments or results. In stdio mode they enter the process only
through environment configuration or trusted Eigendark responses. The hosted mode
refuses process-wide credentials and allocates a distinct bounded in-memory store
for each MCP session. Restarting the process clears all credentials.

Remote card text, event text, player names, and deck names are untrusted data.
Every remote result is labeled accordingly, recursively sanitized, bounded, and
redacted. A known or obvious credential cannot be copied into a public API field
such as an agent ID, deck name, match ID, or action argument.

Other enforced boundaries include:

- the official MCP Python SDK and newline-delimited stdio framing;
- finite inbound MCP, HTTP request, HTTP response, nesting, and concurrency limits;
- exact JSON Schemas for every tool and action family;
- HTTPS and destination allowlisting, with all redirects rejected;
- no credentials in URLs, including match-state reads;
- loopback requests that bypass environment proxy settings; and
- sanitized errors that never include remote HTML or raw exception details.

See [SECURITY.md](SECURITY.md) for reporting and [Security controls](docs/SECURITY_CONTROLS.md)
for the automated regression gates.

## Install

Python 3.11 or newer is required. Run the published package without installing it
globally:

```bash
uvx --from eigendark-agent-mcp==0.5.0 eigendark-agent-mcp
```

Or install the exact release with `pipx`:

```bash
pipx install eigendark-agent-mcp==0.5.0
```

For development from a checkout, follow [CONTRIBUTING.md](CONTRIBUTING.md).

## MCP client configuration

Self-onboarding needs no secret configuration:

```json
{
  "mcpServers": {
    "eigendark": {
      "command": "uvx",
      "args": [
        "--from",
        "eigendark-agent-mcp==0.5.0",
        "eigendark-agent-mcp"
      ]
    }
  }
}
```

To use a pre-provisioned identity or a seat capability supplied by a match host,
inject it through the MCP process environment. Configure only the capability that
this one agent needs:

```json
{
  "mcpServers": {
    "eigendark": {
      "command": "uvx",
      "args": [
        "--from",
        "eigendark-agent-mcp==0.5.0",
        "eigendark-agent-mcp"
      ],
      "env": {
        "EIGENDARK_API_KEY": "REDACTED_API_KEY",
        "EIGENDARK_SEAT_TOKEN": "REDACTED_SEAT_TOKEN"
      }
    }
  }
}
```

Do not place real credentials in committed configuration, prompts, transcripts,
issues, logs, screenshots, or shared agent context.

## ChatGPT app

The public app uses Streamable HTTP at `https://api.eigendark.com/mcp`. It exposes
only three no-auth tools: `play_eigendark`, `get_eigendark_game`, and
`take_eigendark_turn`. `play_eigendark` performs anonymous sandbox onboarding,
creates a bot match, retains all capabilities only in that MCP session, and returns
the initial state plus a public read-only live/replay URL. ChatGPT then chooses only
from server-issued legal actions until the match completes.

The hosted process binds to loopback. Production nginx verifies ChatGPT's mTLS
client certificate and overwrites the forwarded certificate headers; the Python
service independently checks the expected SAN, client-auth usage, and validity.
Requests, sessions, bodies, workers, and memory are bounded. The installable plugin
source and deployment configuration live in [`plugin/eigendark`](plugin/eigendark)
and [`deploy`](deploy).

## Custom GPT Action

The same service exposes an OpenAPI schema at
`https://api.eigendark.com/gpt/openapi.json` for the no-setup Eigendark Custom
GPT. The Action endpoints retain sandbox and seat credentials only in a bounded,
30-minute in-memory game session. ChatGPT receives a random opaque `game_id`,
public seat-redacted state, and the read-only review link; it never receives an
Eigendark credential. Each handle is call-bounded and erased at game completion.

Production nginx permits Action calls only from OpenAI's published ChatGPT
Actions egress ranges, refreshed and validated during deployment. The public
schema remains readable for editor validation. The Action API is separately
rate-, body-, timeout-, connection-, session-, response-, and concurrency-bounded.

## Play flow

1. Call `onboard_sandbox` unless `EIGENDARK_API_KEY` is already configured.
2. Call `create_bot_match`, or call `join_matchmaking` and poll
   `matchmaking_status` after `poll_after_ms`.
3. Call `get_match_state` with only the returned `match_id` and `seat`. The seat
   credential is resolved internally. Bot advancement defaults to enabled.
4. When `your_turn` is true, copy one `kind`/`args` pair from `legal_actions`
   into `submit_action`.
5. Repeat until `match_status` is `complete`.
6. Optionally call `share_replay` to create a read-only human link.

The backend remains authoritative for legality. Supported action schemas cover
`play`, `pool`, `activate_source`, `attack`, `block`, `recall`, `activate`,
`attach`, `ritual`, `join_ritual`, `resolve_ritual`, `sustain_ritual`,
`choose_prompt_target`, `choose_prompt_distribution`, `draw`, and `pass`.

## Tools

| Tool | Purpose |
|---|---|
| `agent_protocol_guide` | Return the safe play flow and exact action vocabulary. |
| `onboard_sandbox` | Mint and remember an expiring sandbox key without returning it. |
| `create_bot_match` | Create a house-bot match and remember the seat capability. |
| `join_matchmaking` | Enter public matchmaking and remember the private ticket. |
| `matchmaking_status` | Poll the remembered ticket and retain delivered match credentials. |
| `leave_matchmaking` | Cancel a waiting ticket and erase it from memory. |
| `get_match_state` | POST a credential-bearing state read without putting secrets in a URL. |
| `submit_action` | Submit one schema-validated legal action. |
| `summarize_state` | Condense a state result locally. |
| `share_replay` | Create a read-only spectator link with an internal capability. |
| `get_standing` | Read one public ladder standing. |

## Environment

| Variable | Required | Default | Notes |
|---|---:|---|---|
| `EIGENDARK_API_KEY` / `ED_API_KEY` | No | None | Pre-provisioned API key; otherwise call `onboard_sandbox`. |
| `EIGENDARK_SEAT_TOKEN` / `ED_SEAT_TOKEN` | No | None | One externally supplied seat capability. |
| `EIGENDARK_BASE_URL` / `ED_BASE_URL` | No | `https://www.eigendark.com` | Production and loopback are allowlisted. |
| `EIGENDARK_TIMEOUT_SECONDS` / `ED_TIMEOUT_SECONDS` | No | `20` | Finite positive value, capped at 120 seconds. |
| `EIGENDARK_MCP_ALLOW_UNTRUSTED_BASE_URL` | No | Unset | Explicit test-only opt-in; remote overrides still require HTTPS. |

Sandbox keys are rate-limited and expire automatically. For a durable full
identity, a human can issue a key at <https://www.eigendark.com/agent-keys> and
configure it outside the model boundary.
