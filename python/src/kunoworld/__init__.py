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
    Plan,
    PlanJob,
    PreparedJob,
    PriceBreakdown,
    Quote,
    ShareLinks,
    Shot,
    StandardVideoJob,
    VideoJob,
    infer_mode,
    parse_share_link,
    share_url_with_key,
)
from .elements import (
    ELEMENT_LIMITS,
    ELEMENT_RULES,
    Element,
    ElementConsent,
    ElementFile,
    ElementFileInfo,
    ElementList,
    Elements,
    ElementsKey,
    ElementUse,
    add_element_lines,
    consent_withdrawn,
    derive_elements_key,
    element_draft_problems,
    element_prompt_line,
    element_roles,
    format_elements_key,
    open_element,
    parse_elements_key,
    rewrap_element_key,
    seal_element,
)

__all__ = [
    "ELEMENT_LIMITS",
    "ELEMENT_RULES",
    "ERROR_CODES",
    "Element",
    "ElementConsent",
    "ElementFile",
    "ElementFileInfo",
    "ElementList",
    "ElementUse",
    "Elements",
    "ElementsKey",
    "GenerationResult",
    "Input",
    "KunoClient",
    "KunoError",
    "Plan",
    "PlanJob",
    "PreparedJob",
    "PriceBreakdown",
    "Quote",
    "ShareLinks",
    "Shot",
    "StandardVideoJob",
    "VideoJob",
    "add_element_lines",
    "consent_withdrawn",
    "derive_elements_key",
    "element_draft_problems",
    "element_prompt_line",
    "element_roles",
    "format_elements_key",
    "infer_mode",
    "open_element",
    "parse_elements_key",
    "parse_share_link",
    "rewrap_element_key",
    "seal_element",
    "share_url_with_key",
]
__version__ = "0.1.0"
