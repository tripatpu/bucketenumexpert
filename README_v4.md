# bucket_exposure_check_v4.py

Org/domain-mapped cloud-storage exposure detector with an **evidence-based
ownership engine**. Authorized bug-bounty recon only.

`bucket_exposure_check.py` (v1/v2) is still present and unchanged; v4 is the
rewrite. Everything below describes **v4**.

---

## The one problem v4 exists to solve

Listing every bucket whose name contains your token produces almost nothing
reportable, because the bucket namespace is global. `acme-assets` might be
yours, or it might belong to an unrelated "Acme" in another country. v3 tried to
answer this with a single check (does an object key mention my domain) plus a
`token in name` substring test — which is both too weak (misses DNS, IAM,
policy and website evidence) and too loose (`arma` matches `pharma-data`).

v4 fixes both directions:

- **Token-boundary matching.** An org token must appear as a *complete delimited
  label*. `arma` no longer matches `pharma-data` or `karma-assets`.
- **Delimiter-bounded content matching.** Short tokens inside object keys must
  be delimiter-bounded, so `examples/` and `template/` do not count as an org
  reference.
- **A weighted, multi-signal ownership score.** A name match is worth 2 points
  and can *never* on its own produce a `CONFIRMED` verdict.

---

## Ownership signals

| Signal | Weight | How it is obtained |
|---|---|---|
| `dns_cname` | 5 | An in-scope hostname's real CNAME chain (DNS-over-HTTPS) points at this bucket |
| `iam_allusers` | 5 | GCS IAM policy is anonymously readable and grants `allUsers` / `allAuthenticatedUsers` |
| `bucket_policy` | 4 | S3 bucket policy is anonymously readable (wildcard principal escalates severity) |
| `key_content` | 4 | Object **keys** contain the org domain / org string (delimiter-bounded) |
| `website_html` | 3 | S3 website / Azure `$web` / GCS virtual-host endpoint serves org-branded HTML |
| `tls_san` | 3 | Certificate SAN/CN served for a CNAME-linked host contains the org domain (runs with `--deep`) |
| `robots_sitemap` | 2 | `robots.txt` / `sitemap.xml` reveal org-specific structure |
| `name_boundary` | 2 | The token is a whole delimited label in the bucket name |

Classification:

| Verdict | Meaning | Report it? |
|---|---|---|
| `CONFIRMED_ORG_BUCKET` | A strong signal (DNS CNAME / IAM `allUsers` / readable policy) or score >= 5 | **Yes** |
| `LIKELY_ORG_BUCKET` | Score 3-4 | Yes, with the signal stated |
| `POSSIBLE_ORG_BUCKET` | Score 1-2 | Only if you can add evidence |
| `NAME_MATCH_UNVERIFIED` | Score 0 | No |

Collision guard: base tokens of <=3 characters, or acronyms, can never be
promoted to `CONFIRMED` on name-shaped evidence alone.

---

## What is actually checked

**Candidates** are always derived from scope tokens — domain, registrable label,
subdomain labels, org words and acronyms — combined with a priority-ordered
~12,000-term business affix list. There is **no bare-wordlist mode**. Ranking
bands guarantee `--max-candidates` keeps the best names: literal token >
token+token > token+affix > token+year, and the literal dotted hostname
(`example.com`) outranks its separator-joined spellings. Dotted bases also take
dot-joined affixes so the ubiquitous `www.example.com` / `assets.example.com`
shapes are generated.

**Existence + anonymous listability**

- **S3** — `https://<b>.s3.amazonaws.com/`, automatic region-redirect following,
  `ListBucketResult` detection, key count and truncation, sample keys as evidence.
- **Azure** — account-level container enumeration, then **per-container blob
  listing**, plus the `$web` static-site endpoint. Account names are normalized
  and de-duplicated.
- **GCP** — JSON API metadata, XML listing, and the virtual-host website
  endpoint for hostname-shaped buckets.
- **DigitalOcean Spaces** — optional (`--providers ...,do`), follows the region 301.

**Anonymous configuration endpoints** (these return 200 only when a concrete
misconfiguration exists, so they are near-zero false positive):

- S3: `?policy ?acl ?cors ?website ?logging ?lifecycle ?versioning ?tagging
  ?encryption ?notification ?publicAccessBlock ?policyStatus` — and with
  `--deep`: `?replication ?inventory ?metrics ?accelerate ?ownershipControls
  ?requestPayment ?analytics`
- GCS: `/storage/v1/b/<b>` (metadata), `/storage/v1/b/<b>/iam` (flags
  `allUsers`), `/storage/v1/b/<b>/acl`
- Azure: `?comp=list`, per-container listing, `?restype=service&comp=properties`,
  `?restype=service&comp=stats`

**Takeover detection** (rewritten): CNAME chains are resolved over
**DNS-over-HTTPS** (Cloudflare + Google) instead of `socket.gethostbyname_ex`,
which cannot see CNAMEs at all. A candidate requires **both** a matching service
CNAME and a matching HTTP error fingerprint from a ~55-service database, and the
CNAME target itself is probed — not just the branded host. Unresolvable CNAME
targets are reported separately as dangling DNS.

---

## Requirements

- Python 3.8+, standard library only (no `pip install`).
- Outbound network access. `--ct` contacts `crt.sh`; `--dns` and the resolver
  fallback use DNS-over-HTTPS.

If your local resolver filters the target host (common on corporate/VPN/ISP
DNS), v4 resolves the host over DoH and retries against that IP **with SNI and
the `Host` header still set to the real hostname**.

---

## Authorized use only

Runs require `--authorized` (with `--scope`) or typing `in scope` interactively.
Authorization is per program on Bugcrowd/HackerOne and never extends to
untargeted scanning. Accessing storage you are not authorized to test may
violate the CFAA (US), Computer Misuse Act (UK), and equivalents.

---

## Usage

### Preview a plan (no storage requests)

```bash
python3 bucket_exposure_check_v4.py --scope scope.txt --authorized --dry-run
```

Writes `findings.candidates.txt` listing the ranked candidate plan so you can
audit exactly what would be probed.

### Interactive

```bash
python3 bucket_exposure_check_v4.py
```

### Full run

```bash
python3 bucket_exposure_check_v4.py \
    --scope scope.txt --authorized \
    --program "Example Corp" \
    --ct --dns --deep \
    --out findings
```

### Resume an interrupted run

```bash
python3 bucket_exposure_check_v4.py --scope scope.txt --authorized \
    --ct --dns --resume --out findings
```

`--resume` replays `findings.stream.jsonl` and skips already-checked targets.

### CI / clean output

```bash
python3 bucket_exposure_check_v4.py --scope scope.txt --authorized \
    --only-confirmed --no-color --out findings
```

---

## Options

| Flag | Default | Description |
|---|---|---|
| `--scope FILE` | — | Authorized tokens/domains, one per line. Omit for interactive mode. |
| `--authorized` | off | **Required with `--scope`.** Affirms the tokens are in the program's brief. |
| `--program NAME` | `unspecified` | Program name for the report header. |
| `--providers LIST` | `aws,azure,gcp` | Any of `aws`, `azure`, `gcp`, `do`. |
| `--ct` | off | crt.sh subdomain expansion; subdomain labels are folded into candidate generation. |
| `--dns` | off | Resolve CT subdomains over DoH; follow CNAME chains; flag takeover candidates. |
| `--deep` | off | Also probe the long-tail S3 configuration endpoints. |
| `--max-affixes N` | `12000` | Cap on the affix wordlist (priority-ordered, so the cap keeps the best). |
| `--max-candidates N` | `4000` | Cap on generated names (score-ranked). |
| `--min-specificity` | `low` | `medium`/`high` skips short, collision-prone tokens. |
| `--rate-delay S` | `0.15` | Seconds slept before each check. |
| `--workers N` | `10` | Concurrent checks. |
| `--timeout S` | `8` | Per-request timeout. |
| `--out BASE` | `findings` | Output basename. |
| `--dry-run` | off | Print the plan; make no storage requests. |
| `--resume` | off | Skip targets already in `BASE.stream.jsonl`. |
| `--show-all` | off | Print every candidate, including non-existent ones. |
| `--only-confirmed` | off | Print only org-confirmed findings. |
| `--check-write` | off | **Dangerous, opt-in.** See below. |
| `--no-color` | off | Disable ANSI colour. |

---

## Output

| File | Contents |
|---|---|
| `BASE.md` | Report-ready, ranked, with the exact evidence per finding. |
| `BASE.json` | Structured results (scope, timestamp, full findings). |
| `BASE.csv` | One row per check, for spreadsheet triage. |
| `BASE.stream.jsonl` | Crash-safe incremental log; also the `--resume` input. |
| `BASE.candidates.txt` | `--dry-run` only: the ranked candidate plan. |

Report sections: takeover candidates -> confirmed org-owned public buckets ->
likely -> possible -> publicly listable but **unverified** org link -> anonymous
config exposure -> dangling CNAMEs -> existing-but-locked inventory ->
name-match-only. Each non-public bucket appears in exactly one section.

Console output (colourised, auto-disabled when piped):

```
[PUBLIC     ] aws-s3       example-assets  sev=HIGH     score=11 CONFIRMED_ORG_BUCKET keys=42 cfgs=1
[exists+cfg ] gcp-storage  example-db      (private) sev=HIGH     cfg=gcs_iam_allusers
[TAKEOVER   ] dev.example.com  -> AWS/S3 (NoSuchBucket fingerprint matched)
```

---

## `--check-write` (read this before using it)

Off by default. When enabled it performs a single anonymous `PUT` of a
randomly-named marker object — **only** against buckets already classified as
org-owned **and** public — then immediately deletes it. Writing to a bucket is a
state change, so only enable this when the program's rules explicitly allow
testing for public write. The report records whether the marker was created and
cleaned up.

---

## Recommended workflow

1. Read the program's scope and rules; put only in-scope tokens into `scope.txt`.
2. Run `--dry-run` first and skim `findings.candidates.txt`.
3. Run with `--ct --dns`, modest `--workers`.
4. Triage in this order: takeover candidates -> `CONFIRMED` -> `LIKELY` ->
   config exposure. Treat the "unverified" section as a *manual* queue.
5. For each real finding, capture the exact request/response — the report already
   recorded the URL, status, sample keys and config responses. **Then stop.**
   Do not download real data and do not claim takeover resources.
6. Report against the program's severity chart.

---

## Severity mapping used

| Condition | Severity |
|---|---|
| Anonymous write on an org-owned bucket | CRITICAL |
| Public list, org-confirmed, keys look sensitive (`.sql`, `.env`, `.bak`, ...) | CRITICAL |
| Public list, org-confirmed, otherwise | HIGH |
| GCS IAM exposes `allUsers` | HIGH |
| S3 bucket policy anonymously readable | HIGH |
| Azure container public | HIGH |
| Public list but org link **unverified** | INFORMATIONAL (do not report yet) |

---

## Tests

Pure-logic tests (no network) — token-boundary matching, token derivation,
candidate ranking, scoring, severity, CNAME linkage, report grouping:

```bash
python3 test_v4_logic.py
```

Live plumbing smoke test (benign requests: one public page, DoH queries, one
clearly-random S3 name) — HTTP layer, DoH + resolver fallback, takeover checker,
all four provider code paths, the runner, resume, and report writing:

```bash
python3 test_v4_smoke.py
```

Expected tail:

```
53 passed, 0 failed
ALL LOGIC TESTS PASSED
```

```
SMOKE TEST PASSED
```

---

## Remediation guidance for target owners

- **AWS S3:** enable Block Public Access at account and bucket level; review
  bucket policies and ACLs; enable default encryption, access logging and
  versioning; remove wildcard principals.
- **Azure Blob:** disable anonymous public access on accounts and containers;
  enforce RBAC / least-privilege SAS; require secure transfer; enable logging.
- **GCP Cloud Storage:** enable uniform bucket-level access; remove `allUsers` /
  `allAuthenticatedUsers` bindings; enable audit logging.
- **Any of them:** audit for dangling CNAMEs pointing at deprovisioned storage
  before someone else claims the name.

---

## License / disclaimer

Provided as-is for lawful, authorized security testing and education. The user
is solely responsible for ensuring they have permission to test any target.
