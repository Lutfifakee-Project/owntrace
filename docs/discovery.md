# Discovery Guide

Discovery builds the endpoint inventory that object mining and testing
consume. All discovered endpoints are scope-filtered; anything outside the
configured targets is dropped with a debug note.

## Sources

### 1. Explicit URLs (`url` source)

`discovery.seeds` (or `--url` on the CLI). Concrete URLs are templated:
identifier-looking path segments become `{placeholders}` named after the
preceding resource (`/orders/o-1001` → `/orders/{order_id}`), and the
concrete value is kept as a sample for later testing.

### 2. HAR captures (`har` source)

HAR 1.2 files — the richest source because they carry real traffic with real
parameter values, headers and bodies.

```bash
# capture with your browser devtools or any proxy, then:
owntrace discover har --file capture.har
```

**Profile attribution:** export the HAR with your OWNTRACE profiles' traffic
and add a header `X-Owntrace-Profile: userA` to requests made as userA
(configurable via `auth.har_profile_header`). Profile-tagged responses feed
*inferred* ownership: an object returned in traffic tagged `userA` is
attributed to that profile. Untagged traffic still contributes endpoints and
response samples — it just cannot establish ownership.

Malformed entries are skipped with notes; a broken file never crashes the
import. Bodies are truncated (64 KiB) and credential-redacted when kept as
samples.

### 3. OpenAPI / Swagger (`openapi` source)

JSON OpenAPI 3.x and Swagger 2.0 documents:

- servers (3.x) or host/basePath/schemes (2.0) become concrete base URLs;
  relative-only specs resolve against your single configured target,
- parameters (path/query/header), including `$ref`-shared parameters,
- request bodies: examples win, otherwise a minimal template is synthesized
  from the schema,
- security schemes map to authentication requirements (bearer, basic,
  header, cookie),
- paths containing `admin`/`internal` are flagged for vertical testing.

### 4. Crawling (`crawl` source)

GET-only, scope-bound crawler with depth (`max_crawl_depth`) and page
(`max_crawl_pages`) budgets. Extracts:

- `<a href>` links (in-scope only),
- `<form>` actions and input names,
- JS-embedded API routes matching `/(api|vN|rest)/...` string literals.

Crawl seeds are separate from url seeds (`discovery.crawl_seeds`) because
crawling sends requests; keep the seeds inside pages you are authorized to
walk.

## Deduplication

Endpoints deduplicate on method + host + normalized path + required query
names. `/orders/o-1001` and `/orders/o-1002` merge into one endpoint with two
samples; `/orders/o-1001/notes` stays distinct. Parameter variations merge
(examples unioned) without losing structure.

## What discovery does NOT do

- It does not test anything or produce findings — run `scan` for that.
- It does not assume a discovered endpoint is authorized for testing — the
  scope engine still gates every future request.
- It does not execute endpoint bodies or follow out-of-scope links.
