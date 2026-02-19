# Audit Verification Runbook

## Purpose

Validate signed GCC audit logs for tamper evidence before incident response, compliance export, or forensic review.

## Inputs

- Audit log file (JSONL), for example: `.GCC/server-audit.jsonl`
- Signing key material used when events were generated:
  - Preferred source: file (`GCC_MCP_AUDIT_SIGNING_KEY_FILE` / `--audit-signing-key-file`)
  - Alternative: environment variable (`GCC_MCP_AUDIT_SIGNING_KEY`)
  - Rotation mode: keyring JSON mapping `event_signing_key_id -> key` (`--signing-keyring-file`)

## Verify a log

```bash
gcc-cli audit-verify \
  --log-file .GCC/server-audit.jsonl \
  --signing-key-file .secrets/audit-signing.key
```

For rotated logs with key IDs:

```bash
gcc-cli audit-verify \
  --log-file .GCC/server-audit.jsonl \
  --signing-keyring-file .secrets/audit-signing-keyring.json
```

For mixed logs (legacy entries without key IDs plus rotated entries), pass both:

```bash
gcc-cli audit-verify \
  --log-file .GCC/server-audit.jsonl \
  --signing-key-file .secrets/legacy-audit-signing.key \
  --signing-keyring-file .secrets/audit-signing-keyring.json
```

On success, CLI returns:

- `status=success`
- `entries_checked=<count>`
- `log_file=<path>`

On failure, CLI returns structured error payload with:

- line number of first failing event
- mismatch reason (chain, hash, or signature)

## Rotation Procedure

Recommended rotation flow:

1. Assign a stable `audit-signing-key-id` to the active signing key in runtime config.
2. Rotate to a new key and key ID; keep previous keys in verifier keyring for historical validation.
3. Verify rotated logs with `--signing-keyring-file` containing all active historical key IDs.
4. For legacy entries without `event_signing_key_id`, provide `--signing-key-file` as fallback.
5. Optionally roll over log files per rotation epoch to simplify long-term key retirement.

This keeps verification deterministic across key epochs while preserving backward compatibility.

## Incident Response Notes

If verification fails:

1. Preserve the original log copy immediately (read-only archive).
2. Record first failing line and error details from verifier output.
3. Compare file checksums against backup/object-store copies.
4. Correlate with deployment/key-rotation timeline to rule out key mismatch.
5. Escalate as potential tampering if mismatch cannot be explained by known operational events.
