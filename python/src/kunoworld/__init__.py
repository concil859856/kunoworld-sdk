"""KunoWorld Python SDK.

    from kunoworld import KunoClient

    client = KunoClient(api_key="...")
    result = client.generate("A lighthouse keeper lights the lamp at dusk", model="h3-turbo", duration_s=6)
    result.save("lighthouse.mp4")

By default (privacy="private") prompts and media are encrypted on your machine to a GPU enclave
whose attestation the SDK verifies first, and the platform only relays ciphertext. With
privacy="standard" they are sent to KunoWorld readable instead: KunoWorld and the GPU provider
can see them. In both modes videos are kept until you delete them (`client.delete(job_id)`).

API keys are for developers' own programs. The KunoWorld website uses email sign-in instead.
"""

from .client import (
    ERROR_CODES,
    GenerationResult,
    Input,
    KunoClient,
    KunoError,
    PreparedJob,
    StandardVideoJob,
    VideoJob,
    infer_mode,
)

__all__ = [
    "ERROR_CODES",
    "GenerationResult",
    "Input",
    "KunoClient",
    "KunoError",
    "PreparedJob",
    "StandardVideoJob",
    "VideoJob",
    "infer_mode",
]
__version__ = "0.1.0"
