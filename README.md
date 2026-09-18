# KunoWorld SDKs

Clients for KunoWorld's private video generation. Both encrypt prompts and reference media on your own device, to a
GPU enclave whose attestation evidence the client checks first, so the gateway only ever relays ciphertext. Both
verify the enclave-signed receipt and decrypt the finished video locally.

| Folder | Package | Runs in | Guide |
|---|---|---|---|
| [python/](python/) | `kunoworld`, with the `kunoworld-mcp` server | Python 3.10+ | [python/README.md](python/README.md) |
| [js/](js/) | `@kunoworld/sdk` | modern browsers and Node.js 20+ | [js/README.md](js/README.md) |
| [skills/kunoworld-video](skills/kunoworld-video/SKILL.md) | an Agent Skill | AI assistants | [SKILL.md](skills/kunoworld-video/SKILL.md) |

> **Development preview.** No confidential GPU worker has run yet, so today these clients talk to development
> gateways whose workers use simulated attestation and may return placeholder video. The TDX and NVIDIA checks are
> tested against Intel's real sample quotes and NVIDIA's real signing certificates, but not yet against a live worker.
> The subnet repository's `SECURITY.md` says what is and is not protected.

## Install

Neither package is on PyPI or npm yet, so install from source.

```bash
# Python: kunoworld needs kuno-protocol, which lives in the subnet repository
uv pip install -e /path/to/kunoworld-subnet/protocol -e /path/to/kunoworld-sdk/python

# JavaScript: build it here, then install the folder from your own project
cd js && npm install && npm run build
npm install /path/to/kunoworld-sdk/js
```

In the KunoWorld development workspace, `uv sync` installs the Python package.

## What the clients do

Both clients offer the same features, and each package's guide has a section per feature.

| Feature | Details |
|---|---|
| **Generate** | Text, image, first and last frame, and reference modes, with LTX-2.5 and MiniMax H3. |
| **Private or Standard, per job** | Private is sealed end to end to an attested enclave. Standard jobs are readable by KunoWorld and the GPU provider. |
| **Storyboards and plans** | Long videos from chained shots. Plans are storyboards the Director writes from a brief inside the enclave; you edit a plan and render it. |
| **Edits** | Retakes of part of a clip, and audio-to-video. |
| **Elements** | Encrypted, reusable characters, products, places, styles and voices. |
| **Quotes and budgets** | The gateway's exact price for a job before anything is spent (`POST /v1/quote`), and a maximum price per job. |
| **Share links** | Make, list and revoke links to your videos, and open links someone sent you. A private video's link carries its key in the `#k=` fragment, which never reaches KunoWorld. |

Key sync between devices and the `/v1/me/*` routes need the website's email sign-in, so the SDKs have no methods for
them.

## What the clients verify

Before encrypting anything to a worker, both clients check two things:
- the worker's Intel TDX quote, against Intel's root;
- its GPUs' NVIDIA-signed attestation results.

The gateway relays the material for these checks but can't forge it (`endorsements`, subnet `PROTOCOL.md`). Given the
subnet owner's public key, the clients also check the owner's signature on the manifest of approved images. None of
these checks trusts the gateway.

## For AI agents

The Python package includes `kunoworld-mcp`, a local MCP server for assistants such as Claude Code, Claude Desktop and
Cursor ([python/README.md](python/README.md), "Agents (MCP)").
- **Where it runs:** on the user's computer, so Private jobs are still encrypted and decrypted there. The assistant
  itself sees what the user types and what the tools return.
- **Spending:** its tools quote the exact price of a job before spending.

The [kunoworld-video](skills/kunoworld-video/SKILL.md) skill teaches an assistant to:
- quote first;
- choose Private or Standard;
- write LTX-2.5 and MiniMax H3 prompts;
- plan storyboards.

## Development

- **JavaScript:** self-contained. `cd js && npm ci && npm run build && npm test`, and CI
  (`.github/workflows/ci.yml`) runs the same on every push.
- **Python:** depends on `kuno-protocol` from the subnet repository, so its tests run in the KunoWorld development
  workspace (`uv run pytest` there) until that package is published.
