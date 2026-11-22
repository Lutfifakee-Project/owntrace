# Vulnerable Demo Walkthrough

A complete, reproducible OWNTRACE run against the bundled deliberately
vulnerable laboratory application. Everything here is loopback-only test data.

## 1. Start the lab application

```bash
# from the repository root
go run ./cmd/mockapp --addr 127.0.0.1:8099 &
```

Users: `alice/pw-alice`, `bob/pw-bob`, `admin/pw-admin` (POST /api/v1/login).

## 2. Set up the project directory

```bash
mkdir ot-demo && cd ot-demo
cp ../examples/vulnerable-demo/owntrace.yaml .
cp ../examples/vulnerable-demo/auth.yaml .
chmod 600 auth.yaml
```

## 3. Provide tokens

The demo config references environment variables:

```bash
export OT_USERA_TOKEN=$(curl -s http://127.0.0.1:8099/api/v1/login \
  -d '{"username":"alice","password":"pw-alice"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')
export OT_USERB_TOKEN=$(curl -s http://127.0.0.1:8099/api/v1/login \
  -d '{"username":"bob","password":"pw-bob"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')
export OT_ADMIN_TOKEN=$(curl -s http://127.0.0.1:8099/api/v1/login \
  -d '{"username":"admin","password":"pw-admin"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')
```

## 4. Preview, then run

```bash
owntrace --config owntrace.yaml --auth auth.yaml scan --dry-run
owntrace --config owntrace.yaml --auth auth.yaml scan
```

## 5. Expected outcome

| Verdict | Finding |
|---|---|
| CONFIRMED (horizontal) | `GET /api/v1/orders/o-1001` — bob reads alice's order |
| CONFIRMED (horizontal) | `GET /api/v1/documents/doc-3001` |
| CONFIRMED (anonymous)  | `GET /api/v1/receipts/r-6001` — no auth needed at all |
| CONFIRMED (vertical)   | `GET /api/v1/admin/stats` — non-admin sees admin data |
| CONFIRMED (cross-tenant) | `GET /api/v1/tenants/t-acme/files/f-9001` |
| CONFIRMED (nested)     | `GET /api/v1/orders/o-1001/notes` |
| CONFIRMED (horizontal) | `/redirect/orders/o-1001` — in-scope redirect followed |
| REJECTED | `GET /api/v1/invoices/inv-2001` — ownership enforced (generic 404) |
| REJECTED | `GET /api/v1/invoices/inv-2001/payments` — nested parent enforced |
| REJECTED | `GET /api/v1/workspaces/ws-2/reports/r-5002` — tenant + parent enforced |
| REJECTED | `GET /api/v1/admin/users/usr-alice` — role enforced |
| REJECTED | `GET /api/v1/echo/o-1001` — decoy (echoes id, carries no object data, identical for everyone) |
| SUSPECTED | `GET /api/v1/cached-docs/doc-3001` — cache artifact (cache-busted retry denies) |
| INCONCLUSIVE | `GET /api/v1/invoices/inv-2001/payments` — requests to `payment`-matching paths are **refused by the safety engine** before send (default destructive-path protection; the finding explains the blocked baseline) |

Note the receipt case: the *horizontal* test rejects it as public content and
the *anonymous* category confirms the exposure — the two verdicts together
tell you exactly what kind of problem it is.

## 6. Inspect results

```bash
owntrace --config owntrace.yaml results list
owntrace --config owntrace.yaml results show --finding F-XXXXXXXX
owntrace --config owntrace.yaml results integrity
$BROWSER owntrace-data/reports/report.html
```

Exit code of the scan is `5` (confirmed findings present) — useful as a CI
gate.
