# KunoWorld SDKs

Clients for KunoWorld's private video generation. Both encrypt prompts and reference media on
your own device, to a GPU enclave whose attestation evidence the client checks first; the
gateway only ever relays ciphertext. Both verify the enclave-signed receipt and decrypt the
finished video locally.

| Folder | Package | Runs in |
|---|---|---|
| [js/](js/) | `@kunoworld/sdk` | modern browsers and Node.js 20+ |
| [python/](python/) | `kunoworld` | Python 3.10+ |

Neither package is published to npm or PyPI yet; each README says how to install from source.

**Development preview.** Real Intel TDX and NVIDIA evidence verification is not built yet, so
today these clients talk to development gateways whose workers use simulated attestation and
may return placeholder video. The encryption, receipts and verification code paths are the
real ones. See the subnet repository's `SECURITY.md` for what is and is not protected.
