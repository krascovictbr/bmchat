> **Language:** [English](README.md) | [Português (BR)](README.pt-BR.md)

# Welcome to bmchat

![bmchat](https://img.shields.io/badge/Rolling%20Release-bmchat-1793D1?style=flat-square&logo=bmchat&logoColor=white)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-0BSD-green)

# bmchat

Telegram-style chat client that uses **only the Bitmessage protocol**
to exchange messages, with a Tkinter graphical interface.

> **Important notice — read before use.** bmchat is an
> **experimental project, under active development, without a security audit**.
> It may contain flaws, bugs and vulnerabilities — including bugs that
> cause messages not to be delivered, corrupt local data or expose more
> metadata than expected. Do not rely on it for anything where your
> safety, freedom or livelihood depends on secrecy. See the
> [Known limitations and risks](#11-known-limitations-and-risks) section for details.

## Table of Contents

1. [What is bmchat](#1-what-is-bmchat)
2. [How a P2P Messenger Works](#2-how-a-p2p-messenger-works)
3. [Proof of Work (PoW)](#3-proof-of-work-pow)
4. [Installation and Running](#4-installation-and-running)
5. [Getting Started](#5-getting-started)
6. [Usage Guide](#6-usage-guide)
7. [Where Data is Stored](#7-where-data-is-stored)
8. [How It Works Internally (Protocol)](#8-how-it-works-internally-protocol)
9. [Code Structure](#9-code-structure)
- [Support](#support)
10. [Testing](#10-testing)
11. [Known Limitations and Risks](#11-known-limitations-and-risks)
12. [Versioning](#12-versioning)
- [Troubleshooting](#troubleshooting)
- [🤖 AI / LLM Configuration](#-ai--llm-configuration)

## 1. What is bmchat

It is a chat program that looks like Telegram on the outside (conversation
list, message bubbles, read receipts), but on the inside it
does not use any company's servers: it talks **directly to the
Bitmessage network**, which is maintained by its own users.

Practical consequences of this:

- There is no sign-up, login, password or "forgot my password".
- Your **identity is a pair of cryptographic keys**. Whoever has the private
  key controls the address; whoever loses it, loses it forever.
- There is no company to complain to if something goes wrong — nor to ask
  to get your data back.

## 2. How a P2P Messenger Works

In a regular messenger (WhatsApp, Telegram), your messages go through
the company's server, which delivers them to the recipient. In a P2P
(*peer-to-peer*) messenger, **everyone connected is
both client and server at the same time**:

- **Nodes and connections.** On launch, bmchat connects to some network nodes
  (addresses discovered via DNS seeds and other nodes). The footer shows
  `Network: E/T` — actually established connections out of attempted.
- **Objects and inventory.** Everything on the network (key requests, keys,
  messages) is an **object**: a block of bytes with an expiration time and
  proof of work. Each node stores the objects it receives (**inventory**)
  and announces to neighbors only the digests (`inv`); those who don't have them request the content
  (`getdata`). This is how your message reaches its recipient: node by
  node, via relay.
- **Streams.** The network is divided into numbered streams so no one needs
  to download everything. Almost everyone uses stream 1, which is the default here.
- **Addresses.** A `BM-...` address embeds version, stream and a digest of the
  public keys. The secret part (private keys) never leaves your
  computer.
- **P2P only.** bmchat works only with direct messages between
  identities and contacts — no channels or groups in the interface.

Because it relies on relay among volunteers, **nothing is instant**: between
publishing and reception by the other side minutes pass, and the first synchronization
(tens of thousands of objects) can take from minutes to hours.

## 3. Proof of Work (PoW)

To prevent spam without requiring sign-up, the network requires **proof
of work**: before publishing any object, your computer must
solve a cryptographic puzzle (find a `nonce` whose double SHA-512
falls below a target). Important points:

- The minimum difficulty is **1000/1000 per object** and cannot be lowered —
  it is a network rule, not a program option.
- **It costs real CPU**: each object (key request, key, message,
  acknowledgment) takes from tens of seconds to a few minutes of
  processing, depending on the machine. bmchat uses multiple cores and shows
  `PoW: N` in the footer while computing.
- That's why conversation symbols matter: **clock** = still computing
  or awaiting key; **✓✓ gray** = published to the network; **✓✓ blue** =
  delivered (ACK received). Right-click on the message shows details.
- Closing the program in the middle of a PoW cancels that computation; the
  pending message retries on its own every 10 minutes.

## 4. Installation and Running

Requirements: Python 3.10+ (tested on 3.14), Tkinter and the contents of
`requirements.txt` (`PySocks`, `pycryptodome`, `ecdsa`).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 run.py
```

Default data directory: `~/.bmchat`. To use another:

```bash
BMCHAT_DATA=/path/to/data python3 run.py
```

## 5. Getting Started

1. On first launch, an identity is already created. Open the ☰ menu →
   **My identity** (or the welcome screen) and **copy your `BM-...` address**
   with the button — this is what you send to contacts by any
   means (email, paper, another messenger).
2. Add someone: ✎ button → **New contact**, pasting their `BM-...`.
3. Open the conversation and write. The message appears immediately with the clock.
4. Behind the scenes: bmchat publishes a request for the contact's public key;
   when it arrives (minutes), the message is encrypted and sent automatically; when
   the other side receives it, the ACK comes and `✓✓` turns blue.

## 6. Usage Guide

- **Conversations**: list on the left with preview, time and unread badge;
  search via magnifying glass; messages in chronological order, newest always at the bottom.
- **Mouse**: right-click on conversation to open/start (Open, Copy address,
  Delete conversation, Remove contact); right-click on
  bubble copies text, deletes message or shows details (state,
  sender, date, expiration, hash).
- **Message time-to-live (TTL)**: every message is born with an expiration
  time — after it, the network discards the object. The default is **1 day**
  for all messages to all contacts; change in System →
  **Message time-to-live…** (1 hour to 21 days, per protocol
  rules; out-of-range values are adjusted and you are notified). Larger TTL requires
  more proof of work and takes longer to send; the ACK expires together.
  Bubble Details show "Expires in".
- **Backup** (button in the identity bar or menu): shows the private
  keys in WIF **with explicit warning** — store in a safe place (paper,
  password manager, offline USB stick); **if lost, it's gone: there is no way
  to recover**. Allows saving to file, copying, importing back and
  exporting/importing **`keys.dat`** (PyBitmessage format) to carry
  keys to other clients — and bring them from there.
- **Proxy / darknet**: Tor (9050/9150), I2P (SOCKS 4447, HTTP 4444) or
  direct connection. The choice is saved and connections are re-established.
- **Network settings**: connection and read timeout, max
  connections and maintenance interval.
- **Network diagnostics**: proxy, uptime, connections (state, version,
  streams, peer rating, clock divergence), total and session traffic,
  inventory; buttons to copy the report and **delete all objects**
  (history is preserved; the network is downloaded again).
- **View log**: shows network and message events (key requests,
  publications, receptions, ACKs) with a copy button — useful for reporting
  issues.
- **Receipt legend**: explains each symbol; remember that
  Bitmessage has no "online" or "last seen" — the contact legend
  only shows whether his public key is known.
- **Footer**: `Network: E/T` (established out of attempted connections),
  `Objects` (stored in DB), `Peers` (known), `PoW` (running
  computations), `Pending` (messages awaiting key) and `Proxy` in use.

## 7. Where Data is Stored

Everything in `~/.bmchat` (or `$BMCHAT_DATA`):

- `bmchat.db` (SQLite): identities and private keys, contacts, subscriptions,
  messages, public keys, network objects, settings.
- `knownnodes.dat`: known peers and reputation (for quick reconnect).

**Back up your keys** (section 6). Anyone with access to these files has
your identity. The database is not encrypted.

## 8. How It Works Internally (Protocol)

- Object types used: `getpubkey`, `pubkey` (v4), `msg` (v1, with
  embedded `ack_data`), `broadcast` (v5); network commands `version`,
  `verack`, `addr`, `inv`, `getdata`, `object`, `ping`, `pong`, `dinv` and
  `error`, in the exact specification formats.
- Cryptography: ECIES (ECDH secp256k1 + AES-256-CBC + HMAC-SHA256) and ECDSA
  in DER/SHA256, interoperable with PyBitmessage (verified by cross
  tests with the original library).
- Input validation: minimum PoW 1000/1000, validity window (past
  −1h, future +28d+3h), maximum size and signature check; anything that fails
  is silently discarded, as on the network.
- ACK: the sender embeds in the message a ready-made object (with PoW); the
  recipient validates and re-announces it; upon seeing the object circulating, the sender
  marks the message as delivered. ACK proves receipt by the
  recipient's program — not that a human has read it.
- Sync persistence: known hashes and objects stay in the DB; on
  reopen, nothing already stored is downloaded again (the first synchronization,
  however, downloads everything once).

## 9. Code Structure

> Refactored with 7 Design Patterns (branch `refactor/design-patterns`). Details in [ARCHITECTURE.md](ARCHITECTURE.md).

```
bmchat/
  version.py
  crypto/
    ecc.py, ecies.py, keys.py, encrypted_db.py
    pow/                 # Strategy Pattern
      strategy.py        # PoWStrategy (ABC)
      standard.py        # StandardPoWStrategy (production)
      mock.py            # MockPoWStrategy (tests)
  protocol/
    const.py, packets.py, objects.py, address.py
    factory.py           # Factory Pattern (ProtocolObjectFactory)
  net/
    proxy.py, peers.py, manager.py, peer.py
    mock.py              # DI Mock (MockNetworkManager)
  core/
    database.py
    client.py            # DI + Observer + State helpers
    events/              # Observer Pattern
      emitter.py         # EventEmitter
      events.py          # NEW_MESSAGE, POW_PROGRESS, ...
    repositories/        # Repository Pattern
      message_repo.py, contact_repo.py, pubkey_repo.py
    models/              # State Pattern
      message.py         # Message model
      states.py          # Pending/Published/Delivered/Failed
  gui/
    app.py               # DI + Observer + CommandHistory
    dialogs.py, theme.py, tooltip.py, notification.py
    commands/            # Command Pattern
      send_message.py, delete_contact.py, backup_keys.py
run.py                   # DI: create_client() builds the graph
ARCHITECTURE.md          # diagram and pattern description
tests/                   # 554 tests (>95% logic: unit 470+ integration 15 stress 15)
ai/                      # 🤖 AI/LLM configs, prompts, skill (see ai/README.md)
  config/ (llms/)        # 9 JSON for OpenAI/Anthropic/Google/Meta/Mistral/DeepSeek/Cohere
  prompts/               # performance, security-audit, refactor, testing, docs, code-review
  skills/bmchat-optimizer.md  # OpenCode skill with bmchat context & guardrails
```

## Support

Menu ☰ → **Support…**: explains the official support channel, shows the
address with a copy button and has **Chat now**, which creates the contact
and opens the conversation directly. The conversation is encrypted like any other.

**Realistic timelines — please read carefully.** Support is handled by people,
in a queue, and each message must traverse the Bitmessage network:

- **Response**: may take **hours or days**. If support is
  investigating a bug or error, the conversation may extend for **days or even
  weeks** (reproducing the issue, testing a fix, publishing an update).
  Resending the same question does not speed things up — each new message goes to the end
  of the queue and pays PoW again.
- **Why it takes time**: bmchat uses **PoW (proof of work) as
  the protocol requires** — minimum difficulty 1000/1000 per object,
  non-negotiable. Each send (key request, key, message, acknowledgment)
  costs tens of seconds to minutes of CPU **on both sides**, and
  P2P relay among volunteer nodes adds more minutes. Add to that
  program closed, computer off or network still syncing, and the
  round-trip cycle of a question/answer easily exceeds hours.
- **What to do while waiting**: leave the program open and connected;
  follow the state via symbols (`…`, `✓✓`, `✓✓`) and *View log*.
  If details are requested, send the contents of *View log* and *Network diagnostics*
  (both have copy buttons).

Opening the support conversation shows a bar with **Send diagnostics**
(also in the Support window): it builds a triage report (version,
system, network, accounts, pending, config, PoW and recent log — **without private
keys or message contents**) and shows everything in a preview. The
**Send to support button is disabled by default** and only enables after checking
"I have read the report above and authorize sending it to support" — **nothing is sent without
that explicit consent**; there are also Copy and Cancel. Sending proceeds
encrypted via the normal message flow.

## 10. Testing

```bash
python3 -m pytest tests/ -q
```

Covers pubkey cycle, sending with ACK, local network between two clients,
DER signatures, PoW against the function extracted from PyBitmessage, chan derivation identical to the reference, ECIES cross-checked with the original `pyelliptic`,
inventory persistence, backup/restore and deletions. Tests speed up
PoW; on the real network 1000/1000 applies. **Tests increase confidence, they do not
prove absence of bugs** (see section 11).

## 11. Known Limitations and Risks

Be direct: this software **is not audited** and was written
iteratively. By using it, assume that:

- **Bugs may exist** that lose messages, duplicate sends, corrupt the
  local database or freeze the UI — and **vulnerabilities** (including
  remote execution via network data, as with any complex network client).
- **Privacy has inherent protocol limits**: messages are
  encrypted, but all nodes relay all objects — size,
  timing and volume of your traffic are visible to anyone observing the network. Without
  Tor/I2P proxy, your IP is exposed to peers. There is no *forward secrecy*:
  if your private key leaks in the future, old recorded messages can
  be read.
- **Anonymity is not guaranteed** by this program; for serious threats use
  audited tools and learn the threat model first.
- **Keys**: loss = permanent loss of identity and associated history
  ; leak = someone else impersonates you and reads what arrives.
- **Network**: slowness of minutes to hours is normal (PoW + relay);
  "fast" here does not mean secure.
- **Compatibility**: the target is the Bitmessage protocol v3/stream 1 and
  objects v1/v4/v5; old addresses (v2/v3) for contacts are rejected.

If you find something wrong, report it with the contents of *View log* and
*Network diagnostics* (built-in copy buttons) — without that data there is almost
no way to investigate.

## 🤖 AI / LLM Configuration

> See [`ai/README.md`](ai/README.md) for the full hub. Branch `feat/ai-llm-config-20260910`.

bmchat ships a dedicated `ai/` folder to make any LLM productive on this codebase:

```
ai/
├── config/ (alias llms/) — 9 JSON configs for 7 LLM families
│   ├── openai-gpt4o.json / openai-gpt4o-mini.json
│   ├── anthropic-claude-3.5-sonnet.json (200k)
│   ├── google-gemini-1.5-pro.json (2M) / flash.json (1M)
│   ├── meta-llama-3.1.json (128k, self-hosted)
│   ├── mistral-large.json (128k, PT-BR native)
│   ├── deepseek-v3.json (128k, cost-efficient)
│   └── cohere-command-r-plus.json (128k, RAG/tool-use)
├── prompts/ — performance, security-audit, refactor, testing, documentation, code-review
└── skills/bmchat-optimizer.md — OpenCode skill (frontmatter) with bmchat context, 7 patterns, bottlenecks, rules
```

Each config (`ai/config/*.json`) is valid JSON (YAML-compatible) with `name/model/provider/context_window/temperature/top_p/system_prompt/prompts(performance/security/refactor/testing/docs)` tuned for bmchat (PoW ECIES secp256k1, streams, inventory, 554 tests). Example:

```bash
cat ai/config/anthropic-claude-3.5-sonnet.json | jq .system_prompt
cat ai/llms/openai-gpt4o.json | jq .prompts.performance
cat ai/prompts/security-audit.md   # copy-paste ready
```

The skill `ai/skills/bmchat-optimizer.md` teaches any agent: what is bmchat (P2P Bitmessage, no servers, PoW 1000/1000, ECIES/ECDSA, streams), architecture (`bmchat/core,crypto,net,gui,protocol,util` + Strategy/Observer/Command/State/Factory/Repository/DI), known bottlenecks (e.g., `gui/app.py:_redraw_chat` virtual scroll, `crypto/pow/standard.py` step 1<<20, `net/manager.py` receiveQueue 10000+4 workers) and rules (never break 554 tests, keep EN/PT-BR sync, ruff/mypy 0, wire compat, 0o700/0o600, Pillow allowlist). For OpenCode the frontmatter makes it auto-discoverable.

```bash
for f in ai/config/*.json; do python3 -m json.tool "$f" > /dev/null && echo "$f OK"; done
python3 -m pytest tests/unit tests/integration tests/stress -q  # 554 passed >95% logic
```

See also `ARCHITECTURE.md` § AI Integration and `SECURITY.md` § AI audit.

## License

**0BSD** (BSD Zero Clause) — the most permissive possible: you may use, copy,
modify and distribute for any purpose, with or without cost, without even needing
to keep credit. See the `LICENSE` file (software is provided "as is",
without warranties).

## 12. Versioning

Rolling release on branch `rolling-release`: each commit is a version, in
format `YYYY.MM.DD+r<commits>.g<sha>[.dirty]`, displayed in *About* and sent
in the protocol user-agent. Without a git repository, it shows `0.0.0+unknown`.

## Updates (via `git pull`)

The program updates via git itself, without downloading anything from elsewhere:

- On launch, it checks in the background whether there are new commits on the remote and
  **notifies with a window** when there are, showing how many.
- Menu ☰ → **Check for updates** does the same check immediately (notifies
  if already up to date, if there is no network or if the copy has no git).
- If accepted, it runs the equivalent of `git pull --ff-only`: it only moves forward if
  it is a fast-forward — **never creates a merge nor touches local changes**; if
  you have modified code, it refuses and explains.
- Once the update is applied, the program **restarts automatically** to the new version.

Equivalent commands in the terminal, from the project folder:

```bash
git pull --ff-only   # update (only fast-forward)
python3 run.py       # open again
```

## Troubleshooting

Order to investigate anything (from most common to rarest):

- **Message stuck on clock**: open the conversation and read the contact legend.
  `awaiting public key…` = the other side has not yet responded
  to the key request (they need to be online and synced; the request is
  republished automatically every 10 min). `PoW: N` in the footer with N > 0 = computation
  in progress, wait.
- **Message does not reach destination**: check if yours left the clock for
  `✓✓` (published) and then `✓✓` blue (delivered to their program). Without
  blue `✓✓`, the problem is on your side (items above). With blue `✓✓` and
  nothing there, the problem is in the other client.
- **Network zero (`Network: 0/X`)**: no internet, firewall blocking outbound,
  wrong proxy or unavailable DNS (DNS seeds need to resolve).
  Try switching between direct and Tor.
- **Divergent clock**: diagnostics reports `DIVERGENT` when your
  clock differs by more than 1h — nodes drop the connection. Fix system date and time.
- **Slow first sync**: tens of thousands of objects;
  watch `Objects` growing in the footer. Do not use *Delete objects* in the middle
  of it (it restarts downloads).
- **Program closed mid-send**: the PoW in progress is cancelled, but the
  pending message retries on its own when reopened.
- **Nothing worked**: copy *View log* and *Network diagnostics* and send to
  support (menu ☰ → *Support…*), along with what you expected to
  happen.
