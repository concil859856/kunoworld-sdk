/** Errors every part of the SDK throws. `client.ts` re-exports them, where they were first defined. */

/**
 * A failed request. `code` is the gateway's machine-readable reason. `details` holds the rest of
 * the error body, for example `reasons` on `private_mode_not_eligible` or `restricted_until` on
 * `account_restricted`.
 */
export class KunoError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "KunoError";
  }

  /** Why private mode isn't available (`private_mode_not_eligible`). */
  get reasons(): string[] {
    const r = this.details.reasons;
    return Array.isArray(r) ? r.filter((x): x is string => typeof x === "string") : [];
  }

  /** Unix seconds until which the account is restricted (`account_restricted`), or null. */
  get restrictedUntil(): number | null {
    return typeof this.details.restricted_until === "number" ? this.details.restricted_until : null;
  }

  /** The request broke the content policy: `content_policy` (Standard) or `safety_blocked` (Private, in the enclave). */
  get isContentPolicy(): boolean {
    return this.code === "content_policy" || this.code === "safety_blocked";
  }

  /** What this code means, when it's one the gateway documents; otherwise null. */
  get explanation(): string | null {
    return ERROR_CODES[this.code as KunoErrorCode] ?? null;
  }
}

/**
 * Error codes callers commonly branch on, and what each means. The gateway may send others;
 * `KunoError.code` is always the raw string.
 */
export const ERROR_CODES = {
  unauthorized: "The API key (or web session) was missing, unknown or revoked.",
  gone: "This endpoint or credential was retired. Studio tokens (kwt_…) no longer work: use an API key, or a same-origin proxy that holds a web session.",
  content_policy: "The request breaks the content policy, so the job wasn't created. All NSFW content is banned in both modes. Nothing was charged.",
  safety_blocked: "The content check inside the enclave blocked the request before rendering. It counts as a strike.",
  content_not_reviewable: "Operators only: this item's content can't be opened, because it isn't a report of child sexual abuse material or sexual content involving a minor, and no matching legal hold covers it.",
  key_not_accepted: "An output_key can be attached to a report only when the reason is csam or sexual_minor.",
  private_mode_not_eligible: "This account can't make private jobs yet; see `reasons`.",
  account_restricted: "The account is restricted; see `restricted_until`.",
  upload_blocked: "A Standard upload was refused by the scan.",
  insufficient_balance: "The balance doesn't cover the job's price.",
  invalid_params: "The request doesn't fit the model's limits (duration, size, frame rate, inputs, or a storyboard's shots).",
  not_found: "No such job, blob or video on this account, or no such share link.",
  deleted: "The owner deleted this video.",
  removed: "The video was removed after a review under the content policy.",
  not_ready: "The job hasn't finished yet.",
  integrity: "What came back didn't match the enclave-signed receipt.",
  decrypt_failed: "The video didn't open with this handle's output key, or with a share link's key.",
  share_unavailable: "The share link no longer works (revoked, expired, video deleted or removed, or account closed; the public answer never says which), or, when making one, the video can't be shared right now.",
  missing_key: "A private share link needs the video's key: the #k=… part of the link, or pass it separately.",
  too_many_shares: "Too many working share links: 20 per video and 1000 per account. Revoke some first.",
  invalid_expiry: "A share link's expiry must be between a minute and ten years from now, in Unix seconds, or null.",
  rate_limited: "Too many requests in the last minute (public share links per network; Elements changes per account). Try again in a minute.",
  no_vault: "Elements are encrypted with key sync's keys, and key sync isn't set up for this account. Turn it on in the studio.",
  vault_changed: "The keys were rotated on another device, or changed while this was being prepared. Get the current key (an Elements key starts again from the studio), then retry.",
  element_exists: "An Element with this id already exists.",
  element_changed: "The Element was changed on another device since it was read. Read it again, then retry.",
  elements_full: "The account holds the most Elements it can (200). Delete one first.",
  storage_full: "Elements' files use the account's 2 GiB. Delete some first.",
  elements_exist: "Key sync can't be turned off while Elements need its keys. Delete the Elements first.",
  invalid_element: "The Element doesn't fit the rules: its name, description, kind, files or consent record.",
  consent_withdrawn: "The person in this Element withdrew consent, so it can't be used in new videos.",
  rules_not_affirmed: "Storing an Element affirms the Elements rules: no public figures, no one under 18, consent for real people, nothing sexual.",
} as const;

export type KunoErrorCode = keyof typeof ERROR_CODES;
