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

Both clients also make, list and revoke share links to your videos, and open links someone sent
you. A private video's link carries its key in the `#k=` fragment, which never reaches KunoWorld;
see "Share links" in each README. Key sync between devices and the `/v1/me/*` routes need the
website's email sign-in, so the SDKs have no methods for them.

**What the clients verify.** Before encrypting anything to a worker, both clients check its Intel TDX quote against
Intel's root and its GPUs' NVIDIA-signed attestation results, using material the gateway relays but can't forge
(`endorsements`, subnet `PROTOCOL.md`). With the subnet owner's public key they also check the owner's signature on the
manifest of approved images. Neither step trusts the gateway.

**Development preview.** No confidential GPU worker has run yet, so today these clients talk to development gateways
whose workers use simulated attestation and may return placeholder video. The TDX and NVIDIA checks are tested
against Intel's real sample quotes and NVIDIA's real signing certificates, not yet against a live worker. See the subnet
repository's `SECURITY.md` for what is and is not protected.
