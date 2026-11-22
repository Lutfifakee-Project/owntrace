# Authentication Guide

## Why independent profiles matter

A cross-account test is only meaningful if the two sides are **provably
different principals**. Two different-looking JWTs can still belong to the
same user (same subject, different sessions) — comparing them would turn
every endpoint into a "vulnerability". OWNTRACE therefore never assumes;
it verifies.

## Profile types

| Type | Credential source |
|---|---|
| `bearer` | `Authorization: Bearer <token>` |
| `jwt` | Same wire format as bearer; name signals intent |
| `header` | Arbitrary headers map (`headers: {X-API-Key: "..."}`) |
| `cookie` | `Cookie: k=v; k2=v2` from a cookies map |
| `basic` | `Authorization: Basic base64(user:pass)` |
| `none` | Anonymous — no credentials |

The anonymous profile is implicit and always available as `anon` — you do not
need to declare it (declaring it is harmless).

## Identity separation verification

Configure a probe per profile:

```yaml
identity:
  endpoint: "https://api.example.com/api/v1/me"   # absolute URL
  method: "GET"
  field: "user.id"        # dot path to the distinguishing value
```

`owntrace auth check` (and every scan) requests the endpoint **with each
profile's credentials**, extracts the field, and compares:

- identical values → profiles are the same user → **distinct=false**
- probe failure / missing field → identity **unverified**

With `auth.require_distinct_identities: true` (the recommended setting), a
scan aborts before testing when separation fails, and logs exactly which
profiles collide. With `verification.require_identity_separation: false`,
testing proceeds but findings are capped at `SUSPECTED` — a CONFIRMED verdict
requires verified distinct identities.

Pick an identity field that is *stable per user* and *not itself a secret*:
user ID, tenant ID, or username are good; e-mail values are automatically
PII-redacted while remaining comparable (stable fingerprints).

## Credential hygiene

- Credentials live in `auth.yaml` (0600, gitignored) or in environment
  variables referenced as `{{ env VAR }}`.
- They are applied to requests at send time only.
- Everything persisted — logs, evidence, findings, database rows, reports —
  passes the redaction layer: `Authorization`, `Cookie`, `Set-Cookie`,
  `X-API-Key` and friends are replaced by `‹redacted:<hash8›` markers; JWTs,
  bearer strings, long hex/base64 secrets and e-mails are scrubbed from
  bodies and free text. The short hash preserves *comparability* (you can
  still see that two redacted values are equal) without revealing the value.
- `owntrace config show` is **always** redacted; there is no plaintext mode.
- SQLite storage never receives raw profile values; the session record
  contains a redacted config snapshot only.

## Refreshing credentials

For long scans against apps with short-lived tokens, use environment
references and refresh the variable, or generate tokens dynamically outside
OWNTRACE (the tool does not perform login flows itself — keeping credential
acquisition out of the scanner keeps audit trails clean).

## Failed authentication handling

If a profile's token expires mid-scan, the owner baseline fails and the
finding is recorded `INCONCLUSIVE` with the reason — never as a false
positive on the application.
