"""KunoWorld Python SDK.

    from kunoworld import KunoClient

    client = KunoClient(api_key="...")
    result = client.generate("A lighthouse keeper lights the lamp at dusk", model="h3-turbo", duration_s=6)
    result.save("lighthouse.mp4")

Prompts and media are encrypted on your machine to a GPU enclave whose
attestation the SDK verifies first. The platform only relays ciphertext.
"""

from .client import GenerationResult, Input, KunoClient, KunoError, PreparedJob, VideoJob, infer_mode

__all__ = ["GenerationResult", "Input", "KunoClient", "KunoError", "PreparedJob", "VideoJob", "infer_mode"]
__version__ = "0.1.0"
