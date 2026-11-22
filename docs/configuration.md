# Configuration Reference

OWNTRACE reads two YAML files. Secrets **must** live only in `auth.yaml`.

## `owntrace.yaml`

```yaml
version: 1                    # schema version, currently 1

session:
  name: "my-first-scan"       # appears in reports
  output_dir: "./owntrace-data"  # SQLite DB + reports live here (chmod 700)
  log_level: "info"           # debug | info | warn | error

scope:
  targets:                    # DENY-BY-DEFAULT: only these hosts are contacted
    - host: "api.example.com" # host[:port], no scheme
      schemes: ["https"]      # default: http + https
      include_paths: ["/api/"]   # empty = all paths
      exclude_paths: ["/api/admin/logout"]
      allowed_methods: ["GET", "HEAD", "OPTIONS"]  # default: global list
      max_requests: 500       # per-target budget
  global_allowed_methods: ["GET", "HEAD", "OPTIONS"]
  blocked_path_patterns:      # regexes; default list blocks destructive ops
    - "(?i)logout"
    - "(?i)delete"
  allow_subdomains: false     # subdomains are NOT auto-authorized
  max_requests_total: 2000    # global budget
  max_crawl_depth: 2
  max_crawl_pages: 50

limits:
  rate_per_second: 5          # global ceiling (also applied per host)
  concurrency: 4              # bounded worker pool (1..64)
  request_timeout_seconds: 15
  max_response_bytes: 2097152 # 2 MiB; larger bodies are truncated + flagged
  max_redirects: 5
  retries: 1                  # transport-error retries only

auth:
  require_distinct_identities: true   # abort testing if separation unverified
  har_profile_header: "X-Owntrace-Profile"  # profile tag read from HAR

discovery:
  sources: ["url", "openapi", "har", "crawl"]
  seeds: []                   # concrete URLs (url source)
  har_files: []
  openapi_files: []           # JSON OpenAPI 3.x or Swagger 2.0
  crawl_seeds: []             # crawl source start pages

objects:
  declared:                   # user-declared ownership
    - profile: userA
      resource: order
      url: "https://api.example.com/api/orders/1001"
      identifiers: ["1001"]
      tenant: ""              # optional tenant id for cross-tenant tests
  mine_collections:           # listing-membership inference
    - profile: userA
      url: "https://api.example.com/api/orders"
      resource: order
      id_fields: ["id", "order_id"]   # default covers common id names
  creation:                   # controlled object creation (confirmed ownership)
    enabled: false            # requires safety.allow_write_methods=true
    endpoint: "https://api.example.com/api/orders"
    method: "POST"
    body_template: '{"item":"owntrace-probe"}'
    content_type: "application/json"
    extract_field: "data.id"  # dot path of the new id in the response
    item_url_template: "https://api.example.com/api/orders/{{id}}"
    profiles: [userA, userB]

verification:
  repeats: 2                  # repeatability control (1..5)
  require_identity_separation: true
  cache_bust: true            # cache-artifact analysis
  anonymous_test: true        # anonymous-access category
  nested_test: true           # nested-resource categorization
  vertical_test: true         # admin-path role tests
  admin_path_patterns: ["/admin", "admin/", "/internal/"]
  min_owner_state_for_confirmed: "declared"  # confirmed|declared|inferred
  max_findings: 500           # per-run cap

safety:
  dry_run: false              # can also be forced per-run with --dry-run
  allow_write_methods: false  # POST/PUT/PATCH/DELETE stay untested until true
  block_destructive_paths: true

report:
  formats: ["json", "markdown"]   # json|markdown|html|csv
  title: "OWNTRACE Authorization Test Report"

retention:
  days: 30                    # results cleanup window
```

### Validation rules (fail fast, exit code 2)

- At least one scope target; hosts without scheme; no duplicate hosts.
- Profile names unique; types from the supported set; `basic` needs
  username+password; declared objects and collections reference existing
  profiles; creation requires `allow_write_methods`.
- `verification.repeats` within 1..5; rate limits within sane bounds.
- Scope regexes must compile.

## `auth.yaml`

```yaml
auth:
  profiles:
    - name: userA
      type: bearer            # bearer|jwt|cookie|header|basic|none
      token: "{{ env OT_USERA_TOKEN }}"
      role: ""                # optional; "admin" enables role baselines
      identity:               # identity-separation probe
        endpoint: "https://api.example.com/api/v1/me"  # absolute URL
        method: "GET"
        field: "user.id"      # dot path to a distinguishing value
    - name: userB
      type: bearer
      token: "{{ env OT_USERB_TOKEN }}"
      identity: { endpoint: "https://api.example.com/api/v1/me", method: "GET", field: "user.id" }
    - name: anon
      type: none
```

- File must have owner-only permissions (0600) — loading **fails** otherwise.
- `cookie` profiles use `cookies: {name: value, ...}`; `header` profiles use
  arbitrary `headers: {Name: value}`.
- Add profiles with `owntrace auth add` instead of editing by hand.

## Environment references

Any secret field accepts `{{ env VARNAME }}`. A missing variable resolves to
an empty string — an empty bearer token fails profile construction with a
clear error before any request is sent.
