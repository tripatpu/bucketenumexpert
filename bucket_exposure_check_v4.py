#!/usr/bin/env python3
"""
bucket_exposure_check.py  (v4 - evidence-scored, org/domain-mapped)
===================================================================
Authorized bug-bounty recon for cloud-storage misconfiguration across AWS S3,
Azure Blob and GCP Cloud Storage (+ optional DigitalOcean Spaces, Alibaba OSS).

WHAT CHANGED IN v4 (vs v3)
--------------------------
DISCOVERY
  1. Domain-aware token derivation. A scope line may be a domain
     (app.example.co.uk), a wildcard (*.example.com), a URL, an org name
     ("Example Corp") or a bare brand. Each form is decomposed into
     registrable-domain, subdomain-label, hyphen/underscore/concatenated and
     acronym variants, so candidates are genuinely derived from YOUR target.
  2. Hostname-shaped candidates. Real buckets are very often the literal
     hostname: example.com, www.example.com, assets.example.com. These are
     emitted first (highest prior probability) instead of being missed.
  3. Weighted, priority-ordered affix list (~12k words) with explicit
     likelihood tiers (core business terms > secondary terms > 2-word
     compounds > 3-word compounds), so --max-candidates always keeps the
     highest-signal names rather than a random slice.
  4. Every candidate carries a discovery score (base specificity x affix
     likelihood). Results are ranked, not just listed.

FALSE-POSITIVE CONTROL (the main point)
  5. Token-boundary matching. A bucket named "pharma-data" no longer counts as
     a hit for the token "arma". The org token must appear as a complete
     delimited label (start / end / "-" / "." / "_").
  6. Multi-signal OWNERSHIP EVIDENCE ENGINE. "The name contains my token" is
     worth almost nothing on a global namespace. v4 gathers independent
     ownership signals and scores them:
         dns_cname        in-scope host CNAMEs to this bucket        (weight 5)
         iam_allusers     GCS IAM exposes allUsers/allAuthenticated  (weight 5)
         bucket_policy    bucket policy anonymously readable         (weight 4)
         key_content      object keys contain the org domain         (weight 4)
         website_html     website endpoint serves org-branded HTML   (weight 3)
         tls_san          certificate SAN contains the org domain    (weight 3)
         robots_sitemap   robots.txt/sitemap.xml reveals org layout  (weight 2)
         name_boundary    token is a whole delimited label           (weight 2)
     Classification: CONFIRMED_ORG_BUCKET / LIKELY_ORG_BUCKET /
     POSSIBLE_ORG_BUCKET / NAME_MATCH_UNVERIFIED. Only the first two are
     "report this"; the remainder are demoted to a manual-review list.
  7. Collision guard: short (<=5 char) and acronym base tokens are marked
     low-specificity and can never be promoted to CONFIRMED on name evidence
     alone.

FINDING VALUE (what actually pays)
  8. Anonymous CONFIGURATION probes. These return 200 only when a concrete
     misconfiguration exists, so they are near-zero false positive:
         S3   ?policy ?acl ?cors ?website ?logging ?lifecycle ?versioning
              ?tagging ?encryption ?notification ?replication ?inventory ...
         GCS  /storage/v1/b/<b>/iam  (allUsers => public IAM)
              /storage/v1/b/<b>/acl, /storage/v1/b/<b> (metadata)
         Azure ?restype=service&comp=properties (logging/CORS),
              ?restype=service&comp=stats, container enumeration, $web site
  9. Per-container Azure enumeration: account list -> container list -> blob
     list, with container names captured as evidence.
 10. Severity mapping per common program charts, plus an optional (OFF by
     default) --check-write that only runs against buckets already classified
     as org-owned AND public; it writes one random marker object, then deletes
     it.

TAKEOVER (rewritten)
 11. Real CNAME chains via DNS-over-HTTPS (Cloudflare + Google) instead of
     socket.gethostbyname_ex, which cannot see CNAME records at all.
 12. ~50-service fingerprint database. A candidate needs BOTH a service CNAME
     and a matching HTTP error fingerprint, and the CNAME target itself is
     probed - not just the branded host.

OPERATIONS
 13. Resumable: --resume replays <out>.stream.jsonl and skips done targets.
 14. Live "see the bucket names" output with colour, --show-all for every
     candidate, --only-confirmed for just the actionable set.
 15. Reports: .md (ranked, report-ready, exact evidence), .json, .csv and
     .stream.jsonl (crash-safe incremental).

WHAT IT STILL DELIBERATELY DOES NOT DO
  * never downloads object contents (keys only, capped, as evidence);
  * never claims a takeover resource;
  * never brute-forces credentials or bypasses access control.
  Proving anonymous listability / a readable bucket policy / a dangling CNAME
  IS the finding. Capture the evidence, report, stop.

AUTHORIZATION
  --authorized (with --scope) or the interactive "in scope" confirmation is
  mandatory. Only test assets the program's brief lists in scope.

USAGE
  Interactive : python3 bucket_exposure_check.py
  Preview     : python3 bucket_exposure_check.py --scope scope.txt --authorized --dry-run
  Full run    : python3 bucket_exposure_check.py --scope scope.txt --authorized --ct --dns --deep --out findings
  Standard library only (3.8+). --ct and --dns use crt.sh and DNS-over-HTTPS.
"""

import argparse
import concurrent.futures
import csv
import datetime
import itertools
import json
import os
import random
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# Windows consoles default to cp1252 and mangle output on ASCII-unfriendly bytes.
if sys.platform == "win32":  # pragma: no cover
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

USER_AGENT = ("bugbounty-scope-recon/4.0 (authorized-testing-only; "
              "contact the program before use)")
MAX_BODY = 262144          # 256 KiB read cap; object CONTENTS are never wanted
EVIDENCE_KEY_CAP = 12      # object KEYS kept as evidence only

# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #
def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


class _C:
    """ANSI colour, auto-disabled when stdout is not a TTY."""
    ON = sys.stdout.isatty()
    R = "\033[91m" if ON else ""
    G = "\033[92m" if ON else ""
    Y = "\033[93m" if ON else ""
    B = "\033[94m" if ON else ""
    M = "\033[95m" if ON else ""
    D = "\033[90m" if ON else ""
    BOLD = "\033[1m" if ON else ""
    X = "\033[0m" if ON else ""


# --------------------------------------------------------------------------- #
# Curated vocabulary -> weighted, priority-ordered affix wordlist
# --------------------------------------------------------------------------- #
# Tier 1 = words that actually show up in real company bucket names, roughly in
# observed-frequency order. Tier 2 = broader business/tech vocabulary.
# Tier 3/4 = compounds. Weights drive the discovery score and guarantee that
# --max-candidates truncation keeps the highest-signal names.
TIER1 = [
    "prod", "production", "dev", "development", "staging", "stage", "qa",
    "test", "uat", "sandbox", "data", "files", "assets", "static", "media",
    "images", "uploads", "backup", "backups", "logs", "public", "internal",
    "private", "web", "www", "cdn", "app", "api", "storage", "config",
    "secrets", "docs", "documents", "reports", "archive", "cache", "temp",
    "deploy", "builds", "artifacts", "content", "share", "downloads",
    "video", "mobile", "analytics", "db", "database",
]

TIER2_DEPARTMENTS = [
    "hr", "finance", "legal", "sales", "marketing", "engineering", "devops",
    "security", "infosec", "product", "design", "support", "ops",
    "operations", "it", "admin", "procurement", "payroll", "compliance",
    "audit", "research", "datascience", "data-science", "growth",
    "customer-success", "partnerships", "biz-dev", "bizdev", "corporate",
    "executive", "people", "recruiting", "talent", "training", "facilities",
    "logistics", "supply-chain", "manufacturing", "quality", "pmo",
    "strategy", "investor-relations", "pr", "comms", "billing", "accounts",
    "accounting", "treasury", "tax", "insurance", "risk", "governance",
    "helpdesk", "onboarding", "hrteam", "financeteam", "legalteam",
]

TIER2_DATA = [
    "file", "dump", "dumps", "export", "exports", "import", "imports",
    "archives", "snapshot", "snapshots", "configs", "configuration", "keys",
    "certs", "certificates", "credentials", "report", "invoices", "invoice",
    "receipts", "contracts", "contract", "records", "record", "sql", "csv",
    "json", "xml", "pii", "phi", "pci", "gdpr", "customer-data",
    "user-data", "employee-data", "hr-data", "financial-data", "sensitive",
    "confidential", "internal-only", "restricted", "classified",
    "private-data", "public-data", "metrics", "audit-logs", "access-logs",
    "error-logs", "event-logs", "telemetry", "metadata", "doc", "forms",
    "templates", "policies", "policy", "manuals", "training-data",
    "test-data", "sample-data", "raw-data", "processed-data",
    "staging-data", "prod-data", "legacy-data", "migration", "migrations",
    "etl", "warehouse", "lake", "datalake", "datawarehouse", "extract",
    "extracts", "attachments", "photos", "thumbnails", "icons", "fonts",
    "scripts", "styles", "js", "css",
]

TIER2_ENVIRONMENTS = [
    "testing", "preprod", "pre-prod", "live", "nonprod", "non-prod",
    "integration", "int", "perf", "performance", "load-test", "canary",
    "beta", "alpha", "rc", "release", "hotfix", "feature", "demo",
    "preview", "local", "external", "prod2", "prod-2", "drsite", "fallback",
]

TIER2_TECH = [
    "asset", "image", "img", "videos", "audio", "upload", "download",
    "tmp", "artifact", "pipeline", "ci", "cd", "cicd", "terraform",
    "ansible", "k8s", "kubernetes", "docker", "helm", "build",
    "release-artifacts", "binaries", "packages", "modules", "microservice",
    "microservices", "serverless", "lambda", "functions", "bucket", "blob",
    "container", "volume", "disk", "s3", "gcs", "object-storage",
    "file-storage", "cold-storage", "hot-storage", "glacier", "email",
    "marketing-assets", "brand", "logos", "pdf", "media-files", "nuxt",
    "react", "node", "python", "static-assets", "web-assets",
]

TIER2_REGIONS = [
    "us", "us-east", "us-east-1", "us-east-2", "us-west", "us-west-1",
    "us-west-2", "eu", "eu-west", "eu-west-1", "eu-central", "eu-central-1",
    "ap", "ap-south", "ap-southeast", "ap-southeast-1", "ap-northeast",
    "ca", "ca-central", "sa-east", "af-south", "me-south", "global", "dr",
    "disaster-recovery", "failover", "primary", "secondary", "replica",
    "backup-region", "uk", "emea", "apac", "latam",
]

TIER2_MISC = [
    "old", "new", "final", "copy", "v1", "v2", "v3", "orig", "original",
    "clone", "mirror", "sync", "replicated", "shared", "team", "teams",
    "project", "projects", "client", "clients", "partner", "vendor",
    "vendors", "customer", "customers", "tenant", "tenants", "corp",
    "corporate", "group", "holdings", "enterprise", "main", "thirdparty",
    "partner-data", "global-bucket", "primary-bucket", "external",
]

NUM_SUFFIXES = ["1", "2", "3", "01", "02", "03", "001"]

# TLD labels must never become base tokens on their own ("example.com" must not
# produce "<tld>-prod"-style noise).
COMMON_TLDS = {
    "com", "net", "org", "io", "co", "ai", "app", "dev", "gov", "edu", "mil",
    "int", "info", "biz", "me", "us", "uk", "de", "fr", "in", "jp", "cn", "au",
    "ca", "br", "ru", "nl", "it", "es", "se", "no", "fi", "ch", "at", "be",
    "pl", "tr", "za", "mx", "kr", "sg", "hk", "tw", "nz", "ie", "il", "dk",
    "cz", "pt", "gr", "ar", "cl", "pe", "xyz", "cloud", "site", "online",
}

# Weights used by the discovery score (base_weight * affix_weight).
W_TIER1, W_TIER2, W_TIER3, W_TIER4, W_YEAR = 10, 6, 3, 2, 5
SPEC_RANK = {"low": 0, "medium": 1, "high": 2}
SPEC_BASE_WEIGHT = {"low": 1, "medium": 2, "high": 3}

# Multi-part public suffixes we care about (compact, zero external deps).
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in",
    "com.mx", "com.ar", "com.co", "com.pe", "com.ve",
    "co.za", "org.za", "gov.za",
    "com.tr", "com.cn", "net.cn", "org.cn", "gov.cn", "com.tw", "com.hk",
    "com.sg", "com.my", "com.ph", "com.vn", "co.th", "co.id", "co.kr",
    "co.nz", "co.il", "com.sa", "com.ae", "com.eg", "com.ng", "com.pk",
    "com.bd", "com.np", "com.lk", "co.ke", "co.tz", "com.gh",
}

# Separators S3/GCS accept in bucket names (Azure strips them entirely).
SEPARATORS = ["-", "_", ""]

STORAGE_CNAME_MARKERS = (
    "s3.amazonaws.com", "s3-website", ".s3.", "s3-external-1.amazonaws.com",
    "blob.core.windows.net", "web.core.windows.net",
    "storage.googleapis.com", "storage.cloud.google.com",
    "digitaloceanspaces.com", "aliyuncs.com",
)

def build_affix_wordlist(cap=12000):
    """Return a priority-ordered list of (word, weight) affix terms.

    Ordering is the contract: the first `cap` entries are the highest-signal
    names, so --max-candidates never discards a good candidate in favour of a
    random one. Compounds are produced lazily with itertools.product and the
    loop stops the instant the cap is reached.
    """
    out, seen = [], set()

    def add(word, weight):
        if word and word not in seen:
            seen.add(word)
            out.append((word, weight))
        return len(out) < cap

    for w in TIER1:
        if not add(w, W_TIER1):
            return out
    for group in (TIER2_DATA, TIER2_ENVIRONMENTS, TIER2_TECH,
                  TIER2_DEPARTMENTS, TIER2_REGIONS, TIER2_MISC):
        for w in group:
            if not add(w, W_TIER2):
                return out
    pair_groups = [
        (TIER1, TIER2_DATA, W_TIER3),
        (TIER2_ENVIRONMENTS, TIER1, W_TIER3),
        (TIER2_ENVIRONMENTS, TIER2_DATA, W_TIER3),
        (TIER2_DEPARTMENTS, TIER2_DATA, W_TIER3),
        (TIER2_TECH, TIER2_DATA, W_TIER3),
        (TIER2_REGIONS, TIER2_DATA, W_TIER3),
        (TIER2_MISC, TIER2_DATA, W_TIER3),
        (TIER2_ENVIRONMENTS, TIER2_TECH, W_TIER4),
        (TIER2_DEPARTMENTS, TIER2_TECH, W_TIER4),
        (TIER2_DEPARTMENTS, TIER2_ENVIRONMENTS, W_TIER4),
    ]
    for left, right, weight in pair_groups:
        for a, b in itertools.product(left, right):
            if a == b:
                continue
            if not add(f"{a}-{b}", weight):
                return out
    return out


# --------------------------------------------------------------------------- #
# HTTP core: no auto-redirect (we WANT to see 301/307 region hints), polite
# backoff that honours 429/503 + Retry-After, hard read cap.
# --------------------------------------------------------------------------- #
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None            # surface the 3xx as HTTPError instead of following


_OPENER = urllib.request.build_opener(_NoRedirect)


def _retry_after(value, fallback):
    if not value:
        return fallback
    value = value.strip()
    if value.isdigit():
        return min(float(value), 20.0)
    try:
        dt = datetime.datetime.strptime(value, "%a, %d %b %Y %H:%M:%S %Z")
        dt = dt.replace(tzinfo=datetime.timezone.utc)
        delta = (dt - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
        return max(0.0, min(delta, 20.0))
    except Exception:
        return fallback


def http_request(url, method="GET", headers=None, body=None, timeout=8,
                 max_tries=3):
    """Return (status, text, headers_dict). status is None on hard failure.

    Redirects are never followed automatically so S3 region redirects can be
    read from the Location/body. Object contents are never requested: callers
    only ask for listings, config endpoints and a couple of small HTML pages.

    If the LOCAL resolver cannot resolve the host (corporate/ISP DNS filtering
    is extremely common when testing real targets), the host is resolved over
    DNS-over-HTTPS and the request is retried against that IP with SNI and the
    Host header still set to the real hostname.
    """
    status, text, hdrs = _http_once(url, method, headers, body, timeout,
                                    max_tries)
    if status is None:
        host = urllib.parse.urlsplit(url).hostname
        if host and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            ip = _doh_resolve_ipv4(host)
            if ip:
                with _DOH_PIN_LOCK, _PinnedHost(host, ip):
                    status, text, hdrs = _http_once(url, method, headers, body,
                                                    timeout, max_tries)
                if status is not None:
                    hdrs["x-recon-doh-fallback"] = ip
    return status, text, hdrs


def _http_once(url, method, headers, body, timeout, max_tries):
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}
    if headers:
        hdrs.update(headers)
    if body is not None and "Content-Type" not in hdrs:
        hdrs["Content-Type"] = "text/plain"
    delay = 0.8
    for attempt in range(max_tries):
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                raw = resp.read(MAX_BODY)
                return (resp.status, raw.decode("utf-8", "replace"),
                        {k.lower(): v for k, v in resp.headers.items()})
        except urllib.error.HTTPError as e:
            if e.code in (429, 503) and attempt < max_tries - 1:
                time.sleep(_retry_after(e.headers.get("Retry-After"), delay)
                           + random.random())
                delay *= 2
                continue
            try:
                raw = e.read(MAX_BODY)
            except Exception:
                raw = b""
            return (e.code, raw.decode("utf-8", "replace"),
                    {k.lower(): v for k, v in (e.headers or {}).items()})
        except Exception:
            if attempt < max_tries - 1:
                time.sleep(delay + random.random())
                delay *= 2
                continue
            return None, "", {}
    return None, "", {}


# --- DNS-over-HTTPS fallback for filtered local resolvers ------------------ #
_DOH_PIN_LOCK = threading.Lock()
_DOH_IP_CACHE = {}


def _doh_resolve_ipv4(host, timeout=6):
    if host in _DOH_IP_CACHE:
        return _DOH_IP_CACHE[host]
    ip = None
    data = doh_query(host, "A", timeout=timeout)
    for ans in (data or {}).get("Answer", []) or []:
        if ans.get("type") == 1 and ans.get("data"):
            ip = ans["data"]
            break
    _DOH_IP_CACHE[host] = ip
    return ip


class _PinnedHost:
    """Temporarily pin one hostname to a known IP in socket.getaddrinfo.

    SNI and the Host header are untouched, so TLS validation still uses the
    real hostname; only name resolution is overridden. Guarded by a lock
    because it patches a process-global.
    """

    def __init__(self, host, ip):
        self.host, self.ip, self._orig = host, ip, None

    def __enter__(self):
        self._orig = socket.getaddrinfo

        def patched(host, port, family=0, type=0, proto=0, flags=0):
            if host == self.host:
                return self._orig(self.ip, port, family, type, proto, flags)
            return self._orig(host, port, family, type, proto, flags)

        socket.getaddrinfo = patched
        return self

    def __exit__(self, *exc):
        if self._orig is not None:
            socket.getaddrinfo = self._orig
        return False


def xml_keys(body, tag="Key", cap=EVIDENCE_KEY_CAP):
    """Object KEYS only, as report evidence. Contents are never fetched."""
    return re.findall(rf"<{tag}>([^<]+)</{tag}>", body)[:cap]


# --------------------------------------------------------------------------- #
# Subdomain-takeover fingerprint database
# (service, cname suffix markers, HTTP error fingerprints)
# A candidate requires BOTH a matching CNAME target AND a matching fingerprint
# on that target, which is what keeps this from flooding you with 404s.
# --------------------------------------------------------------------------- #
TAKEOVER_DB = [
    ("AWS/S3", ("s3.amazonaws.com", "s3-website", "s3-external-1.amazonaws.com",
                ".s3."),
     ("NoSuchBucket", "The specified bucket does not exist")),
    ("GitHub Pages", ("github.io", "github.map.fastly.net"),
     ("There isn't a GitHub Pages site here.",
      "For root URLs (like http://example.com/) you must provide")),
    ("Heroku", ("herokuapp.com", "herokussl.com", "herokudns.com"),
     ("No such app", "heroku | No such app")),
    ("Azure", ("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
               "trafficmanager.net", "blob.core.windows.net", "azurefd.net"),
     ("404 Web Site not found", "Error 404 - Web app not found")),
    ("Shopify", ("myshopify.com",),
     ("Sorry, this shop is currently unavailable.",)),
    ("Netlify", ("netlify.app", "netlify.com"),
     ("Not Found - Request ID",)),
    ("Vercel", ("vercel.app", "now.sh", "vercel-dns.com"),
     ("The deployment could not be found", "DEPLOYMENT_NOT_FOUND")),
    ("CloudFront", ("cloudfront.net",),
     ("Bad request", "ERROR: The request could not be satisfied")),
    ("Fastly", ("fastly.net", "fastlylb.net"),
     ("Fastly error: unknown domain",)),
    ("Surge.sh", ("surge.sh",), ("project not found",)),
    ("Pantheon", ("pantheonsite.io",),
     ("The gods are wise, but do not know of the site which you seek",)),
    ("Tumblr", ("domains.tumblr.com",), ("There's nothing here",)),
    ("WordPress", ("wordpress.com",), ("Do you want to register",)),
    ("Ghost", ("ghost.io",),
     ("The thing you were looking for is no longer here",)),
    ("Zendesk", ("zendesk.com",), ("Help Center Closed",)),
    ("Freshdesk", ("freshdesk.com",), ("May be this is still fresh!",)),
    ("Webflow", ("proxy.webflow.com", "webflow.io"),
     ("The page you are looking for doesn't exist or has been moved",)),
    ("Bitbucket", ("bitbucket.io",), ("Repository not found",)),
    ("Cargo", ("cargocollective.com",), ("404 Not Found",)),
    ("Unbounce", ("unbouncepages.com",),
     ("The requested URL was not found on this server",)),
    ("Readme", ("readme.io",), ("Project doesnt exist... yet!",)),
    ("Statuspage", ("statuspage.io",), ("You are being redirected",)),
    ("Smugmug", ("smugmug.com",), ('"Image Not Found"',)),
    ("Strikingly", ("strikinglydns.com", "s.strikinglydns.com"),
     ("PAGE NOT FOUND",)),
    ("UptimeRobot", ("uptimerobot.com",), ("page not found",)),
    ("Worksites", ("worksites.net",),
     ("Hello! Sorry, this site is no longer available",)),
    ("Tilda", ("tilda.ws", "tildacdn.com"), ("Please renew your subscription",)),
    ("Intercom", ("intercom.help", "custom.intercom.help"),
     ("This page is reserved for artistic purposes",)),
    ("Aha", ("aha.io",),
     ("There is no portal here ... sending you back to Aha!",)),
    ("HelpScout", ("helpscoutdocs.com",),
     ("No settings were found for this company",)),
    ("Pingdom", ("pingdom.com",), ("Sorry, couldn't find the status page",)),
    ("SurveySparrow", ("surveysparrow.com",), ("Account not found",)),
    ("ngrok", ("ngrok.io", "ngrok-free.app"),
     ("ngrok.io not found", "Tunnel not found")),
    ("Smartling", ("smartling.com",), ("Domain is not configured",)),
    ("Teamwork", ("teamwork.com",), ("Oops - We didn't find your site",)),
    ("Agile CRM", ("agilecrm.com",),
     ("Sorry, this page is no longer available",)),
    ("LaunchRock", ("launchrock.com",),
     ("It looks like you may have taken a wrong turn",)),
    ("GetResponse", ("getresponse.com",),
     ("With GetResponse Landing Pages, web forms unlimited",)),
    ("Canny", ("canny.io",), ("Company Not Found",)),
    ("Kajabi", ("kajabi.com",),
     ("The page you were looking for doesn't exist",)),
    ("UserVoice", ("uservoice.com",),
     ("This UserVoice subdomain is currently available",)),
    ("Fly.io", ("fly.dev",), ("404 Not Found",)),
    ("Render", ("onrender.com",), ("Not Found",)),
    ("Railway", ("railway.app",), ("Application not found",)),
    ("Flywheel", ("flywheelsites.com",), ("Not Found",)),
    ("Squarespace", ("squarespace.com",), ("No Such Account",)),
    ("Discourse", ("discourse.org",), ("does not exist",)),
    ("Podbean", ("podbean.com",),
     ("Sorry, this page is no longer available",)),
    ("Sellfy", ("sellfy.com",), ("Page not found",)),
    ("Big Cartel", ("bigcartel.com",),
     ("Oops! We couldn't find that page",)),
    ("Bubble", ("bubbleapps.io",),
     ("This application is not currently available",)),
    ("HubSpot", ("hubspot.net", "hs-sites.com"), ("No webpage was found",)),
    ("Google Cloud Storage", ("storage.googleapis.com",
                              "c.storage.googleapis.com"),
     ("NoSuchBucket", "The specified bucket does not exist")),
    ("DigitalOcean Spaces", ("digitaloceanspaces.com",), ("NoSuchBucket",)),
    ("Alibaba OSS", ("aliyuncs.com",), ("NoSuchBucket",)),
]

DOH_ENDPOINTS = [
    ("https://cloudflare-dns.com/dns-query", "application/dns-json"),
    ("https://dns.google/resolve", "application/dns-json"),
]

TAKEOVER_MAX_CNAME_HOPS = 6

# --------------------------------------------------------------------------- #
# DNS via DNS-over-HTTPS (records real CNAME chains; stdlib socket cannot)
# --------------------------------------------------------------------------- #
def doh_query(name, rrtype="CNAME", timeout=8):
    """Return the parsed JSON answer from Cloudflare/Google DoH, or None."""
    qname = urllib.parse.quote(name, safe="")
    for base, accept in DOH_ENDPOINTS:
        url = f"{base}?name={qname}&type={rrtype}"
        status, body, _ = http_request(url, headers={"Accept": accept},
                                       timeout=timeout, max_tries=2)
        if status == 200 and body:
            try:
                return json.loads(body)
            except Exception:
                continue
    return None


def doh_cname_chain(host, max_hops=TAKEOVER_MAX_CNAME_HOPS):
    """Follow CNAMEs via DoH. Returns (chain, final_target, resolved_bool)."""
    chain, current = [host], host
    for _ in range(max_hops):
        data = doh_query(current, "CNAME")
        if not data:
            break
        nxt = None
        for ans in data.get("Answer", []) or []:
            if ans.get("type") == 5 and ans.get("data"):
                nxt = ans["data"].rstrip(".").lower()
        if not nxt or nxt in chain:
            break
        chain.append(nxt)
        current = nxt
    data = doh_query(current, "A")
    resolved = bool(data and any(a.get("type") == 1
                                 for a in (data.get("Answer") or [])))
    return chain, current, resolved


def tls_san(host, timeout=6):
    """Return the peer certificate SAN/CN names for a host. Ownership signal
    when a bucket is fronted by a custom domain."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        names = [v.lower() for _, v in cert.get("subjectAltName", ())]
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    names.append(value.lower())
        return names
    except Exception:
        return []


# --------------------------------------------------------------------------- #
# Scope atoms -> base tokens with specificity + kind
# --------------------------------------------------------------------------- #
def _spec_from_len(word):
    if len(word) <= 3:
        return "low"
    if len(word) <= 5:
        return "medium"
    return "high"


def _clean_scope_line(line):
    line = line.strip().lower()
    line = re.sub(r"^https?://", "", line)
    line = line.split("/")[0].split("?")[0].split("#")[0]
    line = line.split(":")[0]
    line = line.replace("*.", "").lstrip(".")
    return line.strip()


def registrable_label(domain):
    """app.example.co.uk -> 'example'; shop.example.com -> 'example'."""
    labels = [x for x in domain.split(".") if x]
    if len(labels) < 2:
        return labels[0] if labels else ""
    if ".".join(labels[-2:]) in MULTI_SUFFIXES and len(labels) >= 3:
        return labels[-3]
    return labels[-2]


def scope_atoms(lines):
    """Decompose scope lines into (label, specificity, kind) base tokens.

    Handles domains, wildcards, URLs, org names ("Example Corp") and bare
    brands, producing hyphen/underscore/concatenated/dotted and acronym
    variants. Every candidate later built from these is therefore traceable
    back to something the user explicitly put in scope.
    """
    atoms = {}

    def note(label, spec, kind):
        label = (label or "").strip().lower()
        if not label or not re.fullmatch(r"[a-z0-9][a-z0-9\-_.]{0,62}", label):
            return
        if label not in atoms or SPEC_RANK[spec] > SPEC_RANK[atoms[label][0]]:
            atoms[label] = (spec, kind)

    for raw in lines:
        line = _clean_scope_line(raw)
        if not line:
            continue
        is_domain = bool(re.search(r"[a-z0-9]\.[a-z]{2,}$", line))

        if is_domain:
            labels = [x for x in line.split(".") if x]
            reg = registrable_label(line)
            # kind "domain" == the literal hostname (most common real bucket
            # naming); kind "hostname" == separator-joined variants.
            note(line, "high", "domain")
            for sep in ("-", "_", ""):
                note(sep.join(labels),
                     "high" if len(labels) > 1 else "medium", "hostname")
            if reg:
                note(reg, _spec_from_len(reg), "brand")
            for lbl in labels:
                if lbl and lbl not in MULTI_SUFFIXES and lbl not in COMMON_TLDS \
                        and len(lbl) >= 3 and not lbl.isdigit():
                    note(lbl, _spec_from_len(lbl), "brand")
            if reg and len(labels) >= 2:
                note(reg + labels[-1], "high", "brand")
            if len(labels) >= 2:
                note("".join(x[0] for x in labels if x), "low", "acronym")
        else:
            words = [w for w in re.split(r"[\s._\-]+", line) if w]
            if not words:
                continue
            for sep in ("-", "_", "", "."):
                note(sep.join(words),
                     "high" if len(words) > 1 else _spec_from_len(words[0]),
                     "org")
            for w in words:
                if len(w) >= 3 and not w.isdigit():
                    note(w, _spec_from_len(w), "org")
            if len(words) > 1:
                note("".join(w[0] for w in words), "low", "acronym")

    return [(label, spec, kind) for label, (spec, kind) in atoms.items()]


# --------------------------------------------------------------------------- #
# Scope context: everything the ownership engine needs to decide "is this
# bucket actually this org's?"
# --------------------------------------------------------------------------- #
def build_context(scope_lines):
    domains, org_names = [], []
    for raw in scope_lines:
        line = _clean_scope_line(raw)
        if not line:
            continue
        (domains if re.search(r"[a-z0-9]\.[a-z]{2,}$", line)
         else org_names).append(line)

    strings = set()
    for d in domains:
        strings.add(d)
        for sep in ("-", ""):
            strings.add(d.replace(".", sep))
        reg = registrable_label(d)
        if reg and len(reg) >= 4:
            strings.add(reg)
    for o in org_names:
        if len(o) >= 4:
            strings.add(o)
            strings.add(o.replace(" ", ""))
            strings.add(o.replace(" ", "-"))

    atoms = scope_atoms(scope_lines)
    strong_tokens = sorted({lbl for lbl, spec, _ in atoms
                            if SPEC_RANK[spec] >= 1 and len(lbl) >= 4},
                           key=len, reverse=True)
    return {
        "domains": domains,
        "org_names": org_names,
        "atoms": atoms,
        "search_strings": sorted(s for s in strings if len(s) >= 4),
        "strong_tokens": strong_tokens,
        "primary_domain": domains[0] if domains else "",
    }


def token_boundary(name, token):
    """True only when `token` appears as a COMPLETE delimited label.

    This is the single biggest false-positive fix: without it, the token
    "arma" matches "pharma-data" and "karma-assets".
    """
    if not token or len(token) < 3:
        return False
    return re.search(r"(?:^|[.\-_])" + re.escape(token) + r"(?:$|[.\-_])",
                     name) is not None


def name_boundary_hits(name, ctx):
    return [t for t in ctx["strong_tokens"] if token_boundary(name, t)]


def _contains_delimited(hay, needle):
    """Delimiter-bounded substring test: 'example' inside 'examples/' or
    'myexamplecorp' must NOT count as an org reference."""
    return re.search(r"(?:^|[^a-z0-9])" + re.escape(needle)
                     + r"(?:$|[^a-z0-9])", hay) is not None


def find_org_strings(text, ctx, limit=5):
    """Locate org/domain strings inside arbitrary content (keys, HTML, policy
    JSON). Content is never downloaded - only listings, config and small HTML.

    Short tokens are applied with a delimiter requirement, which is the second
    big false-positive fix after token-boundary matching: object keys are full
    of incidental words like 'examples' or 'template'.
    """
    hay = (text or "").lower()
    hits = []
    for s in ctx["search_strings"]:
        if not s:
            continue
        if len(s) < 8:
            matched = _contains_delimited(hay, s)
        else:
            matched = s in hay
        if matched:
            hits.append(s)
            if len(hits) >= limit:
                break
    return hits


def _valid_s3(name):
    if not re.fullmatch(r"[a-z0-9][a-z0-9.\-_]{1,61}[a-z0-9]", name):
        return False
    if ".." in name or ".-" in name or "-." in name:
        return False
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", name):
        return False        # IP-shaped, never a bucket
    return True


# --------------------------------------------------------------------------- #
# Candidate generation (scored, priority-ordered, always scope-derived)
# --------------------------------------------------------------------------- #
def build_candidates(ctx, max_candidates, years, affix_words,
                     min_specificity="low"):
    """Return [(name, specificity, score, kind), ...] best-first.

    There is deliberately no path that emits a bare generic affix word: every
    candidate contains a base token you supplied (domain, registrable label,
    subdomain label, org word or acronym). Generation order follows
    specificity, then the discovery score sorts the final set so the
    --max-candidates cap always keeps the most promising names.
    """
    floor = SPEC_RANK[min_specificity]
    bases = [a for a in ctx["atoms"] if SPEC_RANK[a[1]] >= floor]
    bases.sort(key=lambda t: (-SPEC_RANK[t[1]], -len(t[0])))

    soft_cap = max(max_candidates * 6, 6000)
    seen, out = set(), []

    # Score bands are deliberately non-overlapping per tier, so the ranking is
    # "literal token > token+token > token+affix > token+year" and the
    # --max-candidates cap can never discard a literal hostname bucket
    # (e.g. example.com / www.example.com) in favour of an affix compound.
    T0, T1, T2, T3 = 2000, 1200, 400, 200
    KIND_BONUS = {"domain": 300, "hostname": 150}

    def add(name, spec, score, kind):
        name = name.lower()
        if name in seen or not _valid_s3(name):
            return len(out) < soft_cap
        seen.add(name)
        out.append((name, spec, score, kind))
        return len(out) < soft_cap

    # Tier 0 - the literal base tokens (highest prior probability). The literal
    # dotted hostname outranks its separator-joined spellings.
    for label, spec, kind in bases:
        score = T0 + SPEC_BASE_WEIGHT[spec] * 10 + KIND_BONUS.get(kind, 0)
        if not add(label, spec, score, kind):
            return _finalize(out, max_candidates)
    # Tier 1 - cross-combinations of two distinct bases (org + product).
    for (a, sa, ka), (b, sb, kb) in itertools.combinations(bases, 2):
        # Skip pairs where one token is a fragment of the other; those produce
        # nonsense like "examplecomexample" without adding coverage.
        if a in b or b in a:
            continue
        spec = sa if SPEC_RANK[sa] < SPEC_RANK[sb] else sb
        score = T1 + SPEC_BASE_WEIGHT[spec] * 10
        for sep in ("-", ""):
            if not add(f"{a}{sep}{b}", spec, score, "combo"):
                return _finalize(out, max_candidates)
    # Tier 2 - one affix term, either side (suffix form is far more common).
    # Iteration is AFFIX-major on purpose: combining the highest-priority affix
    # with every base before moving to the next affix means the soft cap can
    # never be exhausted by one base's combinations, which would otherwise
    # silently drop e.g. every "www.<domain>" style candidate.
    base_meta = []
    for label, spec, kind in bases:
        bw = SPEC_BASE_WEIGHT[spec] + (1 if len(label) >= 8 else 0)
        hb = KIND_BONUS.get(kind, 0) // 2
        # Dotted bases also take dot-joined affixes, otherwise the ubiquitous
        # subdomain-shaped buckets (www.example.com, assets.example.com,
        # cdn.example.com) would never be generated at all.
        seps = SEPARATORS + (["."] if "." in label else [])
        base_meta.append((label, spec, kind, bw, hb, seps))
    for word, aw in affix_words:
        for label, spec, kind, bw, hb, seps in base_meta:
            for sep in seps:
                if not add(f"{label}{sep}{word}", spec, T2 + bw * aw + hb, kind):
                    return _finalize(out, max_candidates)
                if not add(f"{word}{sep}{label}", spec, T2 + bw * aw + hb - 3,
                           kind):
                    return _finalize(out, max_candidates)
    # Tier 3 - years and short numeric suffixes (cheap and very common).
    for label, spec, kind in bases:
        bw = SPEC_BASE_WEIGHT[spec]
        for sep in SEPARATORS:
            for y in list(years or []) + NUM_SUFFIXES:
                if not add(f"{label}{sep}{y}", spec, T3 + bw * W_YEAR, kind):
                    return _finalize(out, max_candidates)
    return _finalize(out, max_candidates)


def _finalize(candidates, max_candidates):
    # Score-descending, then shortest-first (short names are more likely taken).
    candidates.sort(key=lambda t: (-t[2], len(t[0]), t[0]))
    return candidates[:max_candidates]


# --------------------------------------------------------------------------- #
# Ownership evidence engine + severity mapping
# --------------------------------------------------------------------------- #
SIGNAL_WEIGHTS = {
    "dns_cname": 5,        # an in-scope hostname CNAMEs to this bucket
    "iam_allusers": 5,     # GCS IAM exposes allUsers / allAuthenticatedUsers
    "bucket_policy": 4,    # bucket policy anonymously readable
    "key_content": 4,      # object keys reference the org domain
    "website_html": 3,     # website endpoint serves org-branded HTML
    "tls_san": 3,          # certificate SAN contains the org domain
    "robots_sitemap": 2,   # robots.txt / sitemap.xml reveal org structure
    "name_boundary": 2,    # token is a whole delimited label in the name
}
STRONG_SIGNALS = {"dns_cname", "iam_allusers", "bucket_policy"}


def score_ownership(finding, ctx):
    """Attach score / classification / relevance to a finding in place.

    The whole point: "the name contains my token" is worth 2 points, so it can
    never on its own be presented as a confirmed org bucket. Genuine
    ownership needs an independent, non-name signal.
    """
    signals = finding.setdefault("signals", {})
    if "name_boundary" not in signals:
        hits = name_boundary_hits(finding.get("target", ""), ctx)
        if hits:
            signals["name_boundary"] = hits

    score = sum(SIGNAL_WEIGHTS.get(k, 1) for k in signals)
    spec = finding.get("base_specificity", "low")
    has_strong = any(k in signals for k in STRONG_SIGNALS)

    if has_strong or score >= 5:
        cls = "CONFIRMED_ORG_BUCKET"
    elif score >= 3:
        cls = "LIKELY_ORG_BUCKET"
    elif score >= 1 and SPEC_RANK[spec] >= 1:
        cls = "POSSIBLE_ORG_BUCKET"
    else:
        cls = "NAME_MATCH_UNVERIFIED"

    # Collision guard: a 3-5 char / acronym token must never be CONFIRMED on
    # name evidence, no matter how many name-ish signals pile up.
    if cls == "CONFIRMED_ORG_BUCKET" and SPEC_RANK[spec] == 0 and not has_strong:
        cls = "LIKELY_ORG_BUCKET"

    finding["score"] = score
    finding["classification"] = cls
    finding["relevance_confirmed"] = cls in ("CONFIRMED_ORG_BUCKET",
                                            "LIKELY_ORG_BUCKET")
    return finding


def severity_for(finding):
    """Map to the severity wording most programs use, so reports land in the
    right band instead of being argued down."""
    cls = finding.get("classification", "NAME_MATCH_UNVERIFIED")
    access = finding.get("access", "")
    conf = finding.get("config_findings", [])
    keys = finding.get("sample_keys") or []
    sensitive_key = any(re.search(
        r"\.(sql|bak|zip|tar|gz|env|pem|p12|pfx|key|csv|xlsx?|pdf|log|db)$",
        k, re.I) for k in keys)

    if access == "public-write" and cls.startswith(("CONFIRMED", "LIKELY")):
        return "CRITICAL"
    if any(c.get("id") == "gcs_iam_allusers" for c in conf):
        return "HIGH"
    if any(c.get("id") == "s3_bucket_policy" for c in conf):
        return "HIGH"
    if access == "public-list":
        if not cls.startswith(("CONFIRMED", "LIKELY")):
            return "INFORMATIONAL"      # unverified org link => not reportable yet
        return "CRITICAL" if sensitive_key else "HIGH"
    if access == "public-write":
        return "MEDIUM"
    if conf:
        return "MEDIUM" if cls.startswith(("CONFIRMED", "LIKELY")) else "LOW"
    return "INFORMATIONAL"


def config_severity(conf_id):
    return {
        "gcs_iam_allusers": "HIGH",
        "s3_bucket_policy": "HIGH",
        "azure_container_public": "HIGH",
        "s3_cors": "MEDIUM",
        "azure_service_properties": "MEDIUM",
        "s3_website": "MEDIUM",
        "s3_acl": "MEDIUM",
        "s3_logging": "MEDIUM",
        "s3_versioning": "LOW",
        "s3_encryption": "LOW",
        "s3_lifecycle": "LOW",
        "s3_tagging": "LOW",
        "s3_replication": "LOW",
        "s3_notification": "LOW",
        "s3_inventory": "LOW",
        "gcs_metadata": "LOW",
        "gcs_acl": "MEDIUM",
    }.get(conf_id, "LOW")


# --------------------------------------------------------------------------- #
# Run options
# --------------------------------------------------------------------------- #
class Options:
    def __init__(self, **kw):
        self.timeout = kw.get("timeout", 8)
        self.confirm = kw.get("confirm", True)
        self.deep = kw.get("deep", False)
        self.deep_config = kw.get("deep_config", False)
        self.check_write = kw.get("check_write", False)
        self.delay = kw.get("delay", 0.0)
        self.workers = kw.get("workers", 8)


S3_CONFIG_PROBES = [
    ("s3_bucket_policy", "?policy", "bucket policy", ("Statement", "Principal")),
    ("s3_acl", "?acl", "ACL", ("<AccessControlPolicy",)),
    ("s3_cors", "?cors", "CORS configuration", ("<CORSConfiguration",)),
    ("s3_website", "?website", "website configuration", ("<WebsiteConfiguration",)),
    ("s3_logging", "?logging", "server access logging", ("LoggingEnabled",)),
    ("s3_lifecycle", "?lifecycle", "lifecycle configuration", ("<LifecycleConfiguration",)),
    ("s3_versioning", "?versioning", "versioning state", ("<VersioningConfiguration",)),
    ("s3_tagging", "?tagging", "bucket tags", ("<Tagging",)),
    ("s3_encryption", "?encryption", "default encryption", ("<ServerSideEncryptionConfiguration",)),
    ("s3_notification", "?notification", "event notifications", ("<NotificationConfiguration",)),
    ("s3_publicAccessBlock", "?publicAccessBlock", "public access block", ("<PublicAccessBlockConfiguration",)),
    ("s3_policyStatus", "?policyStatus", "policy status", ("IsPublic",)),
]
S3_CONFIG_PROBES_DEEP = [
    ("s3_replication", "?replication", "replication configuration", ("<ReplicationConfiguration",)),
    ("s3_inventory", "?inventory", "inventory configuration", ("<InventoryConfiguration",)),
    ("s3_metrics", "?metrics", "request metrics", ("<MetricsConfiguration",)),
    ("s3_accelerate", "?accelerate", "transfer acceleration", ("<AccelerateConfiguration",)),
    ("s3_ownershipControls", "?ownershipControls", "ownership controls", ("<OwnershipControls",)),
    ("s3_requestPayment", "?requestPayment", "requester-pays", ("Payer",)),
    ("s3_analytics", "?analytics", "storage analytics", ("<AnalyticsConfiguration",)),
]


def _snippet(text, n=400):
    return re.sub(r"\s+", " ", (text or "")).strip()[:n]


def _probe_config(base_url, probes, f):
    """Query anonymous config endpoints. A 200 here means a concrete
    misconfiguration exists, which is why this is near-zero false positive."""
    for cid, qs, label, markers in probes:
        st, body, _ = http_request(base_url + qs, timeout=6, max_tries=2)
        if st != 200:
            continue
        if markers and not any(m in (body or "") for m in markers):
            continue
        entry = {"id": cid, "query": qs, "label": label,
                 "severity": config_severity(cid), "evidence": _snippet(body, 300)}
        if cid == "s3_bucket_policy":
            entry["grants_public"] = bool(
                re.search(r'"Principal"\s*:\s*("\*"|\[\s*"\*"\s*\])', body or ""))
            if entry["grants_public"]:
                entry["severity"] = "HIGH"
                f["signals"]["bucket_policy"] = ["wildcard principal in policy"]
        if cid == "s3_acl" and "AllUsers" in (body or ""):
            entry["note"] = "AllUsers grant present in ACL"
        f["config_findings"].append(entry)


def check_s3(name, spec, ctx, opts):
    f = {"target": name, "provider": "aws-s3", "base_specificity": spec,
         "checked_at": _now_iso(), "signals": {}, "config_findings": []}
    url = f"https://{name}.s3.amazonaws.com/"
    status, body, hdrs = http_request(url, timeout=opts.timeout)

    # S3 answers a wrong-region call with 301/307/400 carrying the real endpoint.
    if status in (301, 307, 400):
        new_url = None
        m = re.search(r"<Endpoint>([^<]+)</Endpoint>", body or "")
        if m:
            new_url = "https://" + m.group(1).strip().rstrip("/") + "/"
        else:
            m = re.search(r"<Region>([^<]+)</Region>", body or "")
            if m:
                new_url = f"https://{name}.s3.{m.group(1).strip()}.amazonaws.com/"
        if new_url and new_url != url:
            url = new_url
            status, body, hdrs = http_request(url, timeout=opts.timeout)

    region = hdrs.get("x-amz-bucket-region") or ""
    f.update(url=url, http_status=status, region=region)

    if status is None:
        f.update(exists="unknown", access="unknown", listable="unknown",
                 note="network error / timeout")
        return f
    if status == 404 or "NoSuchBucket" in (body or ""):
        f.update(exists="no", access="missing", listable="n/a",
                 evidence="NoSuchBucket")
        return f
    if "InvalidBucketName" in (body or ""):
        f.update(exists="no", access="missing", listable="n/a",
                 evidence="InvalidBucketName (name is not a legal S3 bucket)")
        return f
    if status == 403 or "AccessDenied" in (body or ""):
        f.update(exists="yes", access="private",
                 evidence="403 AccessDenied (bucket exists, listing denied)")
    elif status == 200 and "<ListBucketResult" in (body or ""):
        f.update(exists="yes", access="public-list", listable="PUBLIC",
                 evidence="anonymous ListBucketResult (objects are listable)")
        keys = xml_keys(body)
        f["sample_keys"] = keys
        m = re.search(r"<KeyCount>(\d+)</KeyCount>", body or "")
        f["key_count"] = int(m.group(1)) if m else len(keys)
        f["truncated"] = "<IsTruncated>true</IsTruncated>" in (body or "")
        hits = find_org_strings(" ".join(keys), ctx)
        if hits:
            f["signals"]["key_content"] = hits
    elif status == 200:
        f.update(exists="yes", access="unknown",
                 evidence="200 without ListBucketResult (root may be an object)")
    else:
        f.update(exists="maybe", access="unclear", evidence=f"HTTP {status}")

    if f.get("exists") != "yes":
        return f

    probes = list(S3_CONFIG_PROBES) + (
        S3_CONFIG_PROBES_DEEP if opts.deep_config else [])
    _probe_config(f["url"], probes, f)

    # Website endpoint: an S3 static site almost always carries org branding.
    wregion = region or "us-east-1"
    for host in (f"{name}.s3-website-{wregion}.amazonaws.com",
                 f"{name}.s3-website.{wregion}.amazonaws.com"):
        st, bd, _ = http_request(f"http://{host}/", timeout=opts.timeout,
                                 max_tries=2)
        if st == 200 and "<" in (bd or ""):
            f["website_url"] = f"http://{host}/"
            title = re.search(r"<title[^>]*>(.*?)</title>", bd or "", re.I | re.S)
            f["website_title"] = _snippet(title.group(1), 120) if title else ""
            hits = find_org_strings(bd, ctx)
            if hits:
                f["signals"]["website_html"] = hits
            for rp in ("robots.txt", "sitemap.xml"):
                rs, rb, _ = http_request(f"http://{host}/{rp}", timeout=5,
                                         max_tries=1)
                if rs == 200 and rb.strip():
                    f["signals"].setdefault("robots_sitemap", []).append(
                        f"{rp}: {_snippet(rb, 120)}")
            break

    if opts.check_write:
        _s3_write_test(name, f, opts)
    return f


def _s3_write_test(name, f, opts):
    """OPT-IN only, and only ever against a bucket that is already public AND
    classified as org-owned. Writes one tiny random marker object, then
    deletes it. Never run this without explicit program authorization."""
    if not f.get("relevance_confirmed"):
        f["write_test"] = "skipped (bucket not classified as org-owned)"
        return
    marker = "recon-probe-" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                                      for _ in range(12)) + ".txt"
    put_url = f"{f['url']}{marker}"
    st, body, _ = http_request(put_url, method="PUT", body=b"recon-probe",
                               timeout=opts.timeout, max_tries=1)
    f["write_test"] = f"PUT {st}"
    if st == 200:
        f["access"] = "public-write"
        f["evidence"] = (f.get("evidence", "") +
                         " | ANONYMOUS WRITE SUCCEEDED (marker object created "
                         "then deleted)").strip(" |")
        http_request(put_url, method="DELETE", timeout=opts.timeout, max_tries=1)
        f["write_test"] = "PUT 200 -> deleted marker (cleaned up)"


def _azure_account(name):
    """Azure storage account names: 3-24 lowercase alphanumerics, no hyphens."""
    acct = re.sub(r"[^a-z0-9]", "", name.lower())[:24]
    return acct if len(acct) >= 3 else None


def check_azure(name, spec, ctx, opts):
    acct = _azure_account(name)
    if not acct:
        return None
    base = f"https://{acct}.blob.core.windows.net/"
    f = {"target": acct, "provider": "azure-blob", "base_specificity": spec,
         "checked_at": _now_iso(), "signals": {}, "config_findings": [],
         "url": base}

    # 1. account-level container enumeration (anonymous) - unusual if it works
    status, body, _ = http_request(base + "?comp=list", timeout=opts.timeout)
    f["http_status"] = status
    if status is None:
        f.update(exists="unknown", access="unknown", listable="unknown")
        return f
    if status == 200 and "EnumerationResults" in (body or ""):
        f.update(exists="yes", access="public-list", listable="PUBLIC",
                 evidence="anonymous account-level container enumeration "
                          "succeeded")
        f["config_findings"].append({
            "id": "azure_container_public", "label": "account-level container listing",
            "severity": "HIGH", "evidence": _snippet(body, 300)})
    elif status in (403, 409) or "AuthenticationFailed" in (body or ""):
        f.update(exists="yes", access="private",
                 evidence=f"HTTP {status} (account exists, anonymous denied)")
    else:
        f.update(exists="maybe", access="unclear",
                 evidence=f"HTTP {status}")

    containers = re.findall(r"<Container>\s*<Name>([^<]+)</Name>", body or "")
    if containers:
        f["containers"] = containers[:25]
        hits = find_org_strings(" ".join(containers), ctx)
        if hits:
            f["signals"]["key_content"] = hits

    if f.get("exists") != "yes":
        return f

    # 2. per-container public blob listing (the actual high-value finding)
    public_containers = []
    for c in containers[:10]:
        cu = f"{base}{c}?restype=container&comp=list&maxresults=10"
        st, bd, _ = http_request(cu, timeout=opts.timeout, max_tries=2)
        if st == 200 and ("<EnumerationResults" in (bd or "")
                          or "<Blobs>" in (bd or "")):
            public_containers.append(c)
            keys = xml_keys(bd, tag="Name")
            f["config_findings"].append({
                "id": "azure_container_public", "label": f"public container: {c}",
                "severity": "HIGH", "url": cu, "sample_keys": keys[:8],
                "evidence": _snippet(bd, 200)})
            hits = find_org_strings(" ".join(keys), ctx)
            if hits:
                f["signals"].setdefault("key_content", []).extend(hits)
    if public_containers:
        f["public_containers"] = public_containers
        if f.get("access") != "public-list":
            f["access"] = "public-list"
            f["listable"] = "PUBLIC"
            f["evidence"] = (f.get("evidence", "") +
                             f" | public container(s): {public_containers}").strip(" |")

    # 3. anonymous service properties / stats (logging, CORS, metrics config)
    for cid, qs, label, markers in (
        ("azure_service_properties", "?restype=service&comp=properties",
         "storage service properties", ("<StorageServiceProperties",)),
        ("azure_service_stats", "?restype=service&comp=stats",
         "storage service stats", ("<StorageServiceStats",)),
    ):
        st, bd, _ = http_request(base + qs, timeout=6, max_tries=1)
        if st == 200 and (not markers or any(m in (bd or "") for m in markers)):
            f["config_findings"].append({
                "id": cid, "query": qs, "label": label,
                "severity": config_severity(cid), "evidence": _snippet(bd, 250)})

    # 4. Azure static website ($web) - strong org-branding signal
    for host in (f"{acct}.z13.web.core.windows.net", f"{acct}.web.core.windows.net"):
        st, bd, _ = http_request(f"https://{host}/", timeout=opts.timeout,
                                 max_tries=2)
        if st == 200 and "<" in (bd or ""):
            f["website_url"] = f"https://{host}/"
            title = re.search(r"<title[^>]*>(.*?)</title>", bd or "", re.I | re.S)
            f["website_title"] = _snippet(title.group(1), 120) if title else ""
            hits = find_org_strings(bd, ctx)
            if hits:
                f["signals"]["website_html"] = hits
            break
    return f


def check_gcp(name, spec, ctx, opts):
    base = f"https://storage.googleapis.com/{name}/"
    api = f"https://storage.googleapis.com/storage/v1/b/{name}"
    f = {"target": name, "provider": "gcp-storage",
         "base_specificity": spec, "checked_at": _now_iso(),
         "signals": {}, "config_findings": [], "url": base}

    # Metadata first: GCS JSON API gives a clean exists / not-exists verdict.
    st, body, _ = http_request(api, timeout=opts.timeout)
    f["http_status"] = st
    if st == 404 or "NoSuchBucket" in (body or ""):
        f.update(exists="no", access="missing", listable="n/a",
                 evidence="NoSuchBucket")
        return f
    if st == 400 and re.search(r"invalid|InvalidBucketName|InvalidArgument",
                               body or ""):
        f.update(exists="no", access="missing", listable="n/a",
                 evidence="HTTP 400 (name is not a legal GCS bucket)")
        return f
    if st == 200:
        f["exists"] = "yes"
        loc = re.search(r'"location"\s*:\s*"([^"]+)"', body or "")
        f["region"] = loc.group(1) if loc else ""
        f["metadata"] = _snippet(body, 300)
        f["config_findings"].append({
            "id": "gcs_metadata", "label": "anonymous bucket metadata",
            "severity": "LOW", "evidence": f["metadata"]})
        hits = find_org_strings(body or "", ctx)
        if hits:
            f["signals"]["key_content"] = hits
    elif st in (401, 403):
        f.update(exists="yes", access="private",
                 evidence=f"HTTP {st} (bucket exists, anonymous denied)")
    else:
        f.update(exists="maybe", access="unclear", evidence=f"HTTP {st}")

    # XML listing endpoint (works for buckets with public object listing).
    st2, body2, _ = http_request(base + "?list-type=2&max-keys=25",
                                 timeout=opts.timeout)
    if st2 == 200 and ("<ListBucketResult" in (body2 or "")
                       or "<Contents>" in (body2 or "")):
        f.update(exists="yes", access="public-list", listable="PUBLIC",
                 evidence="anonymous ListBucketResult via XML API")
        keys = xml_keys(body2, tag="Key")
        f["sample_keys"] = keys
        f["key_count"] = len(keys)
        f["truncated"] = "<IsTruncated>true</IsTruncated>" in (body2 or "")
        hits = find_org_strings(" ".join(keys), ctx)
        if hits:
            f["signals"]["key_content"] = hits
    elif st2 == 200:
        f["exists"] = f.get("exists", "yes")

    if f.get("exists") != "yes":
        return f

    # IAM policy: allUsers / allAuthenticatedUsers is a genuine HIGH finding.
    st3, body3, _ = http_request(api + "/iam", timeout=opts.timeout, max_tries=2)
    if st3 == 200 and "bindings" in (body3 or ""):
        members = re.findall(r'"(allUsers|allAuthenticatedUsers)"', body3 or "")
        roles = re.findall(r'"role"\s*:\s*"([^"]+)"', body3 or "")
        entry = {"id": "gcs_iam_allusers", "label": "readable bucket IAM policy",
                 "severity": "HIGH" if members else "MEDIUM",
                 "members": sorted(set(members)), "roles": roles[:8],
                 "evidence": _snippet(body3, 300)}
        f["config_findings"].append(entry)
        if members:
            f["signals"]["iam_allusers"] = sorted(set(members))
        hits = find_org_strings(body3 or "", ctx)
        if hits:
            f["signals"].setdefault("policy_strings", []).extend(hits)

    # Object/bucket ACL (may expose owner identity / allUsers grants).
    st4, body4, _ = http_request(api + "/acl", timeout=6, max_tries=1)
    if st4 == 200 and "items" in (body4 or ""):
        entry = {"id": "gcs_acl", "label": "readable object ACL",
                 "severity": config_severity("gcs_acl"),
                 "evidence": _snippet(body4, 250)}
        if "allUsers" in (body4 or ""):
            entry["note"] = "allUsers present in ACL"
        f["config_findings"].append(entry)

    # Hostname-shaped bucket => virtual-host website endpoint.
    if "." in name:
        st5, body5, _ = http_request(f"https://{name}.storage.googleapis.com/",
                                     timeout=opts.timeout, max_tries=2)
        if st5 == 200 and "<" in (body5 or ""):
            f["website_url"] = f"https://{name}.storage.googleapis.com/"
            title = re.search(r"<title[^>]*>(.*?)</title>", body5 or "", re.I | re.S)
            f["website_title"] = _snippet(title.group(1), 120) if title else ""
            hits = find_org_strings(body5, ctx)
            if hits:
                f["signals"]["website_html"] = hits
    return f


DO_REGIONS = ("nyc3", "sfo3", "ams3", "sgp1", "fra1", "syd1", "blr1", "tor1")


def check_do(name, spec, ctx, opts):
    """DigitalOcean Spaces: try the bare virtual host, follow the region 301."""
    url = f"https://{name}.digitaloceanspaces.com/?list-type=2&max-keys=25"
    f = {"target": name, "provider": "do-spaces", "base_specificity": spec,
         "checked_at": _now_iso(), "signals": {}, "config_findings": [],
         "url": url}
    st, body, hdrs = http_request(url, timeout=opts.timeout)
    if st in (301, 307):
        loc = hdrs.get("location", "")
        if loc:
            f["url"] = loc if loc.startswith("http") else "https://" + loc
            st, body, hdrs = http_request(f["url"], timeout=opts.timeout)
    f["http_status"] = st
    if st == 200 and "<ListBucketResult" in (body or ""):
        keys = xml_keys(body, tag="Key")
        f.update(exists="yes", access="public-list", listable="PUBLIC",
                 evidence="anonymous ListBucketResult (DO Spaces)",
                 sample_keys=keys, key_count=len(keys))
        hits = find_org_strings(" ".join(keys), ctx)
        if hits:
            f["signals"]["key_content"] = hits
    elif st == 404 or "NoSuchBucket" in (body or ""):
        f.update(exists="no", access="missing", listable="n/a",
                 evidence="NoSuchBucket")
    elif st == 403 or "AccessDenied" in (body or ""):
        f.update(exists="yes", access="private", evidence="403 AccessDenied")
    else:
        f.update(exists="maybe", access="unclear", evidence=f"HTTP {st}")
    return f


def check_takeover(host, ctx, opts):
    """Dangling-CNAME takeover candidate detection.

    Requires BOTH a service CNAME and a matching HTTP error fingerprint on the
    CNAME target -- that pairing is what separates a real candidate from the
    thousands of harmless storage CNAMEs. Flags only; never claims anything.
    """
    chain, final, resolved = doh_cname_chain(host)
    f = {"target": host, "provider": "dns-takeover", "base_specificity": "high",
         "checked_at": _now_iso(), "signals": {}, "config_findings": [],
         "cname_chain": " -> ".join(chain), "cname_final": final,
         "target_resolves": resolved}

    if len(chain) < 2:
        f.update(exists="n/a", access="n/a", finding="no-cname",
                 confidence="info", evidence="host has no CNAME")
        return f

    joined = " ".join(chain[1:]).lower()
    service, fingerprints = None, ()
    for svc, markers, fps in TAKEOVER_DB:
        if any(m in joined for m in markers):
            service, fingerprints = svc, fps
            break

    if not service:
        if not resolved:
            f.update(exists="unknown", access="dangling-dns",
                     finding="DANGLING-CNAME-UNRESOLVED", confidence="medium",
                     evidence="CNAME target does not resolve; verify whether "
                              "the service can be reclaimed before reporting")
            return f
        f.update(exists="yes", access="n/a",
                 finding="cname-no-known-service", confidence="info",
                 evidence="CNAME present but not a known takeover service")
        return f

    f["service"] = service
    hits = []
    for url in (f"http://{host}/", f"https://{final}/"):
        st, body, _ = http_request(url, timeout=opts.timeout, max_tries=2)
        low = (body or "").lower()
        for fp in fingerprints:
            if fp.lower() in low:
                hits.append({"url": url, "http_status": st, "fingerprint": fp})
                break

    if hits:
        f.update(finding="SUBDOMAIN-TAKEOVER-CANDIDATE", confidence="high",
                 exists="no", access="dangling",
                 evidence=f"{service} error fingerprint matched -> resource "
                          f"behind '{host}' appears unclaimed")
        f["fingerprint_hits"] = hits
    else:
        f.update(finding=f"{service}-cname-claimed", confidence="info",
                 exists="yes", access="n/a",
                 evidence="CNAME points at the service but no takeover "
                          "fingerprint matched (service looks live)")
    return f


# --------------------------------------------------------------------------- #
# Certificate Transparency expansion (in-scope domains only)
# --------------------------------------------------------------------------- #
def ct_subdomains(domain, limit=400, timeout=25):
    """Passive subdomain discovery for a domain you explicitly put in scope."""
    url = "https://crt.sh/?q=%25." + urllib.parse.quote(domain) + "&output=json"
    st, body, _ = http_request(url, timeout=timeout, max_tries=2)
    if st != 200 or not body:
        return set()
    out = set()
    try:
        for row in json.loads(body):
            for nv in str(row.get("name_value", "")).splitlines():
                nv = nv.strip().lower().lstrip("*.").rstrip(".")
                if "@" in nv or not nv:
                    continue
                if nv == domain or nv.endswith("." + domain):
                    out.add(nv)
    except Exception:
        return set()
    return set(sorted(out)[:limit])


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
PROVIDERS = {
    "aws": check_s3,
    "azure": check_azure,
    "gcp": check_gcp,
    "do": check_do,
}


def _task_key(provider, name):
    # Azure collapses many candidate spellings onto one account name; dedupe so
    # the same account is not hammered dozens of times.
    return (provider, _azure_account(name) if provider == "azure" else name)


def _print_finding(f, show_all=False, only_confirmed=False):
    cls, access = f.get("classification", ""), f.get("access", "")
    prov, tgt = f.get("provider", ""), f.get("target", "")
    score = f.get("score", 0)

    if f.get("finding") == "SUBDOMAIN-TAKEOVER-CANDIDATE":
        print(f"{_C.R}{_C.BOLD}[TAKEOVER] {_C.X}{_C.R}{tgt}{_C.X}"
              f"  -> {f.get('service')} ({_snippet(f.get('evidence'), 60)})")
        return
    if f.get("finding") == "DANGLING-CNAME-UNRESOLVED":
        print(f"{_C.Y}[dangling] {tgt}  -> {f.get('cname_chain','')}{_C.X}")
        return
    if only_confirmed and not f.get("relevance_confirmed"):
        return

    if access in ("public-list", "public-write"):
        extra = f"keys={f.get('key_count', len(f.get('sample_keys') or []))}"
        if f.get("config_findings"):
            extra += f" cfgs={len(f['config_findings'])}"
        print(f"{_C.R}{_C.BOLD}[{access.upper():11}]{_C.X} "
              f"{prov:12} {_C.BOLD}{tgt}{_C.X}  "
              f"sev={str(f.get('severity','?')):13} score={score} {cls} {extra}")
    elif f.get("exists") == "yes":
        cfgs = f.get("config_findings") or []
        if cfgs:
            names = ",".join(sorted({c["id"] for c in cfgs}))[:60]
            print(f"{_C.Y}[exists+cfg ]{_C.X} {prov:12} {tgt}  ({access}) "
                  f"sev={str(f.get('severity','?')):13} cfg={names}")
        else:
            print(f"{_C.B}[exists     ]{_C.X} {prov:12} {tgt}  ({access}) "
                  f"score={score} {cls}")
    elif show_all:
        print(f"{_C.D}[missing    ]{_C.X} {prov:12} {tgt}{_C.X}")


def run(candidates, takeover_hosts, provider_names, ctx, opts, jsonl_path=None,
        resume_done=None, show_all=False, only_confirmed=False):
    resume_done = resume_done or set()
    tasks, seen = [], set()
    for name, spec, score, kind in candidates:
        for p in provider_names:
            if p not in PROVIDERS:
                continue
            key = _task_key(p, name)
            if key in seen:
                continue
            seen.add(key)
            tasks.append(("bucket", p, name, spec, score, kind))
    for host in takeover_hosts:
        key = ("dns-takeover", host)
        if key in seen:
            continue
        seen.add(key)
        tasks.append(("takeover", "dns-takeover", host, "high", 0, "subdomain"))

    if resume_done:
        before = len(tasks)
        tasks = [t for t in tasks if f"{t[1]}|{t[2]}" not in resume_done]
        print(f"[i] --resume: skipped {before - len(tasks)} checked targets")

    print(f"[i] {len(tasks)} network checks queued "
          f"({len(candidates)} candidates x {len(provider_names)} provider(s), "
          f"+ {len(takeover_hosts)} takeover host(s))\n")

    findings, lock = [], threading.Lock()
    jsonl_f = open(jsonl_path, "w", encoding="utf-8") if jsonl_path else None
    done = 0

    def do(task):
        _, provider, name, spec, _score, _kind = task
        if opts.delay:
            time.sleep(opts.delay)
        if provider == "dns-takeover":
            return check_takeover(name, ctx, opts)
        return PROVIDERS[provider](name, spec, ctx, opts)

    try:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, opts.workers)) as ex:
            futures = [ex.submit(do, t) for t in tasks]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    res = fut.result()
                except Exception as exc:          # one target must not kill a run
                    res = {"target": "?", "provider": "?",
                           "error": repr(exc), "checked_at": _now_iso(),
                           "signals": {}, "config_findings": []}
                done += 1
                if not res:
                    continue
                with lock:
                    findings.append(res)
                    if jsonl_f:
                        jsonl_f.write(json.dumps(res, default=str) + "\n")
                        jsonl_f.flush()
                _print_finding(res, show_all, only_confirmed)
                if done % 250 == 0:
                    print(f"{_C.D}... {done}/{len(tasks)} checked, "
                          f"{len(findings)} findings so far{_C.X}")
    except KeyboardInterrupt:
        print(f"\n{_C.Y}[!] interrupted - partial results already saved to "
              f"{jsonl_path}{_C.X}")
    finally:
        if jsonl_f:
            jsonl_f.close()

    # An in-scope subdomain that CNAMEs to a bucket is the strongest ownership
    # signal available, so link it back BEFORE scoring/classification, then
    # corroborate with the TLS certificate served for those hostnames.
    link_cname_to_buckets(findings)
    if opts.deep:
        enrich_tls_san(findings, ctx, timeout=opts.timeout)
    for f in findings:
        if f.get("provider") == "dns-takeover":
            f["severity"] = f.get("severity", "HIGH"
                                  if f.get("finding") ==
                                  "SUBDOMAIN-TAKEOVER-CANDIDATE" else
                                  "INFORMATIONAL")
            continue
        score_ownership(f, ctx)
        f["severity"] = severity_for(f)
    return findings


def link_cname_to_buckets(findings):
    buckets = [f for f in findings
               if f.get("provider") in ("aws-s3", "gcp-storage", "azure-blob",
                                        "do-spaces")]
    for tf in (f for f in findings if f.get("provider") == "dns-takeover"):
        if len(tf.get("cname_chain", "").split(" -> ")) < 2:
            continue
        hay = (tf["cname_chain"] + " " + (tf.get("cname_final") or "")).lower()
        for b in buckets:
            tgt = (b.get("target") or "").lower()
            if not tgt:
                continue
            # the chain string uses " -> " separators, so the delimiters here
            # must include whitespace, not just dots/hyphens.
            if re.search(r"(?:^|[\s.\-])" + re.escape(tgt) + r"(?:$|[\s.\-])",
                         hay):
                lst = b["signals"].setdefault("dns_cname", [])
                if tf["target"] not in lst:
                    lst.append(tf["target"])


def enrich_tls_san(findings, ctx, timeout=6):
    """Add the `tls_san` ownership signal for CNAME-linked buckets.

    When an in-scope hostname CNAMEs to a bucket, the certificate served for
    that hostname is strong corroboration if its SAN/CN contains the org's own
    domain. Runs only for buckets that already carry a dns_cname signal, so it
    costs at most a couple of TLS handshakes per run.
    """
    cache = {}
    for f in findings:
        if f.get("provider") == "dns-takeover":
            continue
        hosts = (f.get("signals") or {}).get("dns_cname") or []
        for host in hosts[:2]:
            if host not in cache:
                cache[host] = tls_san(host, timeout=timeout)
            names = cache[host]
            if not names:
                continue
            hits = [n for n in names
                    if n in ctx["search_strings"]
                    or any(n == d or n.endswith("." + d) or n.lstrip("*.") == d
                           for d in ctx["domains"])]
            if hits:
                f["signals"].setdefault("tls_san", [])
                for h in sorted(set(hits))[:3]:
                    if h not in f["signals"]["tls_san"]:
                        f["signals"]["tls_san"].append(h)
    return findings


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def classify_buckets(findings):
    out = {"confirmed": [], "likely": [], "possible": [], "unverified": [],
           "public_unverified": [], "config_only": [], "inventory": [],
           "takeover": [], "dangling": []}
    for f in findings:
        if f.get("provider") == "dns-takeover":
            if f.get("finding") == "SUBDOMAIN-TAKEOVER-CANDIDATE":
                out["takeover"].append(f)
            elif f.get("finding") == "DANGLING-CNAME-UNRESOLVED":
                out["dangling"].append(f)
            continue
        if f.get("exists") != "yes" and f.get("access") not in (
                "public-list", "public-write"):
            continue
        cls = f.get("classification", "NAME_MATCH_UNVERIFIED")
        public = f.get("access") in ("public-list", "public-write")
        # Non-public buckets belong to exactly one inventory list, never both.
        if not public:
            if f.get("config_findings"):
                out["config_only"].append(f)
            else:
                out["inventory"].append(f)
            continue
        if not f.get("relevance_confirmed"):
            out["public_unverified"].append(f)
        elif cls == "CONFIRMED_ORG_BUCKET":
            out["confirmed"].append(f)
        elif cls == "LIKELY_ORG_BUCKET":
            out["likely"].append(f)
        elif cls == "POSSIBLE_ORG_BUCKET":
            out["possible"].append(f)
        else:
            out["unverified"].append(f)
    for k in out:
        out[k].sort(key=lambda f: (-(f.get("score") or 0), f.get("target", "")))
    return out


def _signals_md(f):
    sig = f.get("signals") or {}
    if not sig:
        return "- Ownership signals: none (name match only)"
    lines = []
    for k, v in sig.items():
        val = "; ".join(str(x) for x in v) if isinstance(v, list) else str(v)
        lines.append(f"- Ownership signal `{k}` (+{SIGNAL_WEIGHTS.get(k, 1)}): "
                     f"{_snippet(val, 200)}")
    return "\n".join(lines)


def _bucket_md(f, heading="###"):
    L = [f"{heading} `{f['target']}` - {f['provider']} "
         f"[{f.get('severity','?')}]"]
    L.append(f"- URL: {f.get('url','')}")
    L.append(f"- Classification: **{f.get('classification','?')}** "
             f"(score {f.get('score',0)}) | base specificity: "
             f"{f.get('base_specificity','?')}")
    L.append(f"- Access: {f.get('access','?')} | HTTP {f.get('http_status')}"
             + (f" | region {f.get('region')}" if f.get("region") else ""))
    if f.get("evidence"):
        L.append(f"- Evidence: {f['evidence']}")
    L.append(_signals_md(f))
    if f.get("website_url"):
        L.append(f"- Website endpoint: {f['website_url']} "
                 f"(title: {f.get('website_title') or 'n/a'})")
    if f.get("sample_keys"):
        L.append("- Sample object keys (evidence; contents NOT retrieved): "
                 f"`{f['sample_keys']}`")
    if f.get("key_count"):
        L.append(f"- Keys observed: {f['key_count']}"
                 + (" (truncated - bucket is larger)" if f.get("truncated")
                    else ""))
    if f.get("containers"):
        L.append(f"- Containers: `{f['containers']}`")
    for c in (f.get("config_findings") or []):
        L.append(f"- **Config exposure** `{c.get('id')}` [{c.get('severity')}] "
                 f"{c.get('label','')}"
                 + (f" (public grant: {c['grants_public']})"
                    if c.get("grants_public") is not None else ""))
        if c.get("url"):
            L.append(f"  - URL: {c['url']}")
        if c.get("sample_keys"):
            L.append(f"  - Sample keys: `{c['sample_keys']}`")
        if c.get("evidence"):
            L.append(f"  - Response: `{_snippet(c['evidence'], 260)}`")
    L.append(f"- Checked: {f.get('checked_at','')}")
    L.append("")
    return "\n".join(L)


def write_report(findings, program, out_base, scope_lines):
    with open(out_base + ".json", "w", encoding="utf-8") as fh:
        json.dump({"program": program, "generated_at": _now_iso(),
                   "scope": scope_lines, "findings": findings}, fh, indent=2,
                  default=str)

    with open(out_base + ".csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["provider", "target", "severity", "classification",
                    "score", "access", "http_status", "exists",
                    "base_specificity", "signals", "config_findings",
                    "key_count", "sample_keys", "url"])
        for f in findings:
            w.writerow([
                f.get("provider", ""), f.get("target", ""),
                f.get("severity", ""),
                f.get("classification", f.get("finding", "")),
                f.get("score", ""), f.get("access", ""),
                f.get("http_status", ""), f.get("exists", ""),
                f.get("base_specificity", ""),
                ";".join(f.get("signals", {}).keys()),
                ";".join(c.get("id", "") for c in f.get("config_findings") or []),
                f.get("key_count", ""),
                " | ".join(f.get("sample_keys") or [])[:300],
                f.get("url", "")])

    g = classify_buckets(findings)
    n_pub = sum(len(g[k]) for k in ("confirmed", "likely", "possible",
                                    "unverified", "public_unverified"))
    L = [f"# Cloud storage exposure recon - {program}",
         f"_Generated {_now_iso()}. Authorized testing only._", "",
         f"**Scope:** {', '.join(scope_lines)}", "",
         f"**Checks performed:** {len(findings)}  |  "
         f"**Publicly listable:** {n_pub}  |  "
         f"**Org-confirmed public:** {len(g['confirmed'])}  |  "
         f"**Org-likely public:** {len(g['likely'])}  |  "
         f"**Config exposure:** {len(g['config_only'])}  |  "
         f"**Takeover candidates:** {len(g['takeover'])}", "",
         "> Classification is evidence-based. `CONFIRMED` requires an "
         "independent ownership signal (a DNS CNAME from an in-scope host, a "
         "readable bucket policy, or a GCS `allUsers` IAM binding). A bucket "
         "whose name merely contains your token is explicitly NOT confirmed.",
         ""]

    if g["takeover"]:
        L.append("## 1. Subdomain-takeover candidates (verify, then report)\n")
        for f in g["takeover"]:
            L.append(f"### `{f['target']}` -> {f.get('service')}")
            L.append(f"- CNAME chain: `{f.get('cname_chain','')}`")
            L.append(f"- CNAME target resolves: {f.get('target_resolves')}")
            L.append(f"- Evidence: {f.get('evidence','')}")
            for h in f.get("fingerprint_hits", []):
                L.append(f"  - `{h['url']}` HTTP {h['http_status']} matched "
                         f"fingerprint `{h['fingerprint']}`")
            L.append("- Do NOT claim the resource. Verify, then report; claim "
                     "only with program approval and release after triage.\n")

    section = 2
    for key, title in (
        ("confirmed", "Confirmed org-owned public buckets (report these)"),
        ("likely", "Likely org-owned public buckets"),
        ("possible", "Possible org buckets (one weak signal)"),
    ):
        if g[key]:
            L.append(f"## {section}. {title}\n")
            for f in g[key]:
                L.append(_bucket_md(f))
            section += 1

    if g["public_unverified"]:
        L.append(f"## {section}. Publicly listable, org link UNVERIFIED "
                 "(check before reporting)\n")
        L.append("_The name matches a scope token but no independent ownership "
                 "signal was found. These are frequently unrelated buckets "
                 "sharing a common word - inspect the sample keys yourself._\n")
        for f in g["public_unverified"]:
            L.append(_bucket_md(f))
        section += 1
    if g["config_only"]:
        L.append(f"## {section}. Anonymous configuration exposure "
                 "(listing denied, config still readable)\n")
        for f in g["config_only"]:
            L.append(_bucket_md(f))
        section += 1
    if g["dangling"]:
        L.append(f"## {section}. Dangling CNAMEs (unresolved targets)\n")
        for f in g["dangling"]:
            L.append(f"- `{f['target']}` -> `{f.get('cname_chain','')}` "
                     f"({f.get('evidence','')})")
        L.append("")
        section += 1
    if g["inventory"]:
        L.append(f"## {section}. Existing but not anonymously listable "
                 "(recon inventory)\n")
        for f in g["inventory"]:
            L.append(f"- `{f['target']}` ({f['provider']}) - "
                     f"{f.get('access')}")
        L.append("")
        section += 1
    if g["unverified"]:
        L.append(f"## {section}. Exists, name-match only (lowest priority)\n")
        for f in g["unverified"][:200]:
            L.append(f"- `{f['target']}` ({f['provider']}) - "
                     f"{f.get('access')} | specificity="
                     f"{f.get('base_specificity')}")
        L.append("")

    if not any(g[k] for k in ("takeover", "confirmed", "likely", "possible",
                              "public_unverified", "config_only")):
        L.append("_No publicly listable org buckets, anonymous config exposure "
                 "or takeover candidates were found. See the inventory "
                 "sections above._\n")

    L += ["## Method",
          "- Candidates come ONLY from scope-derived tokens (domain, "
          "registrable label, subdomain labels, org words, acronyms) combined "
          "with a priority-ordered business-term affix list; there is no bare "
          "wordlist mode.",
          "- Ownership is scored from independent signals: `dns_cname` (DNS "
          "over HTTPS CNAME chain from an in-scope host), `iam_allusers`, "
          "`bucket_policy`, `key_content`, `website_html`, `tls_san`, "
          "`robots_sitemap`, `name_boundary`. A name match alone scores 2 and "
          "can never yield CONFIRMED.",
          "- Object CONTENTS are never downloaded: only listings, config "
          "endpoints, small HTML pages and object KEYS as evidence.",
          "- Anonymous config endpoints probed: S3 `?policy ?acl ?cors "
          "?website ?logging ?lifecycle ?versioning ?tagging ?encryption "
          "?notification ?publicAccessBlock ?policyStatus` (more with "
          "`--deep`); GCS `/storage/v1/b/<b>`, `/iam`, `/acl`; Azure "
          "`?comp=list`, per-container listing, "
          "`?restype=service&comp=properties`.",
          "",
          "### Next step",
          "Capture the exact request/response for each confirmed item, then "
          "STOP. Do not download real data and do not claim takeover "
          "resources. File against the program's severity chart.",
          ""]

    with open(out_base + ".md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))
    return g


def load_resume(jsonl_path):
    done = set()
    if not jsonl_path or not os.path.exists(jsonl_path):
        return done
    with open(jsonl_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if row.get("provider") and row.get("target"):
                done.add(f"{row['provider']}|{row['target']}")
    return done


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
CT_SKIP_LABELS = {"www", "mail", "smtp", "ftp", "ns1", "ns2", "webmail",
                  "autodiscover", "localhost", "cpanel", "whm"}


def interactive_scope():
    print("=== Cloud storage exposure detector (authorized recon only) ===")
    program = input("Program name: ").strip() or "unspecified"
    print("Enter org names / domains IN SCOPE (one per line, blank to finish).")
    print('Examples: example.com  *.example.com  "Example Corp"  example')
    tokens = []
    while True:
        line = input("  > ").strip()
        if not line:
            break
        tokens.append(line)
    if not tokens:
        sys.exit("No targets entered.")
    print(f"\nProgram: {program}")
    for t in tokens:
        print(f"   - {t}")
    print("\nConfirm every target above is listed IN SCOPE in the program "
          "brief and you are authorized to test it.")
    if input("Type 'in scope' to proceed: ").strip().lower() != "in scope":
        sys.exit("Not confirmed in scope. Aborting.")
    return program, tokens


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Org/domain-mapped cloud-storage exposure detector with "
                    "evidence-based ownership scoring (authorized recon only).")
    p.add_argument("--scope", help="Scope file, one token/domain per line "
                                  "(omit for interactive mode).")
    p.add_argument("--authorized", action="store_true",
                   help="Required with --scope: affirms every token is in the "
                        "program's brief.")
    p.add_argument("--program", default="unspecified")
    p.add_argument("--providers", default="aws,azure,gcp",
                   help="Comma list from: aws,azure,gcp,do (default: three "
                        "major clouds).")
    p.add_argument("--ct", action="store_true",
                   help="Expand scope via Certificate Transparency (crt.sh) and "
                        "fold subdomain labels into candidate generation.")
    p.add_argument("--dns", action="store_true",
                   help="Resolve CT subdomains over DNS-over-HTTPS, follow real "
                        "CNAME chains and flag takeover candidates.")
    p.add_argument("--deep", action="store_true",
                   help="Also probe the long-tail S3 config endpoints.")
    p.add_argument("--max-affixes", type=int, default=12000,
                   help="Cap on the affix wordlist (default 12000; "
                        "priority-ordered, so the cap keeps the best).")
    p.add_argument("--max-candidates", type=int, default=4000,
                   help="Cap on generated candidates (default 4000; "
                        "score-ranked so the cap keeps the best names).")
    p.add_argument("--min-specificity", choices=["low", "medium", "high"],
                   default="low",
                   help="Drop base tokens below this specificity. Use 'medium' "
                        "or 'high' to skip short/collision-prone tokens.")
    p.add_argument("--rate-delay", type=float, default=0.15,
                   help="Per-check delay in seconds (default 0.15).")
    p.add_argument("--workers", type=int, default=10)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--out", default="findings")
    p.add_argument("--dry-run", action="store_true",
                   help="Show the candidate plan and make no storage requests.")
    p.add_argument("--resume", action="store_true",
                   help="Skip targets already present in <out>.stream.jsonl.")
    p.add_argument("--show-all", action="store_true",
                   help="Print every candidate, including non-existent ones.")
    p.add_argument("--only-confirmed", action="store_true",
                   help="Print only findings classified as org-confirmed.")
    p.add_argument("--check-write", action="store_true",
                   help="DANGEROUS/OPT-IN: test anonymous WRITE on buckets "
                        "already classified org-owned and public, writing then "
                        "deleting one marker object. Only with explicit program "
                        "authorization.")
    p.add_argument("--no-color", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.no_color:
        for attr in ("R", "G", "Y", "B", "M", "D", "BOLD", "X"):
            setattr(_C, attr, "")

    if args.scope:
        if not args.authorized:
            sys.exit("Refusing to run: pass --authorized to affirm the --scope "
                     "tokens are in the program's brief. Untargeted scanning "
                     "is not authorized.")
        try:
            with open(args.scope, encoding="utf-8") as fh:
                scope_lines = [ln.strip() for ln in fh
                               if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            sys.exit(f"Cannot read scope file: {exc}")
        if not scope_lines:
            sys.exit("Scope file is empty.")
        program = args.program
    else:
        program, scope_lines = interactive_scope()

    print(f"{_C.BOLD}[i] Program: {program}{_C.X}")
    print(f"[i] Scope: {', '.join(scope_lines)}")

    # Certificate Transparency expansion (in-scope domains only).
    subdomains = set()
    domains = [d for d in (_clean_scope_line(x) for x in scope_lines)
               if re.search(r"[a-z0-9]\.[a-z]{2,}$", d)]
    if args.ct and domains:
        for d in domains:
            found = ct_subdomains(d)
            print(f"[ct] {d}: +{len(found)} subdomains from crt.sh")
            subdomains |= found
        extra = []
        apex = set(domains)
        for s in sorted(subdomains):
            if s in apex:
                continue                     # the apex is not a subdomain
            lbl = s.split(".")[0]
            if (len(lbl) >= 5 and lbl not in CT_SKIP_LABELS
                    and re.fullmatch(r"[a-z0-9][a-z0-9\-]{3,30}", lbl)):
                extra.append(lbl)
        extra = list(dict.fromkeys(extra))[:40]
        if extra:
            print(f"[ct] folding {len(extra)} subdomain labels into candidate "
                  f"generation: {', '.join(extra[:12])}"
                  + (" ..." if len(extra) > 12 else ""))
            scope_lines = scope_lines + extra
    takeover_hosts = sorted(subdomains) if args.dns else []

    ctx = build_context(scope_lines)
    top_atoms = sorted(ctx["atoms"], key=lambda a: -SPEC_RANK[a[1]])[:14]
    print(f"[i] Derived base tokens ({len(ctx['atoms'])}): "
          + ", ".join(f"{l}({s})" for l, s, _ in top_atoms)
          + (" ..." if len(ctx["atoms"]) > 14 else ""))

    affixes = build_affix_wordlist(cap=args.max_affixes)
    print(f"[i] Affix wordlist: {len(affixes)} priority-ordered business terms")

    this_year = datetime.datetime.now(datetime.timezone.utc).year
    years = [str(y) for y in range(this_year - 4, this_year + 1)]
    candidates = build_candidates(ctx, args.max_candidates, years, affixes,
                                  args.min_specificity)

    providers = [x.strip() for x in args.providers.split(",") if x.strip()]
    unknown = [p for p in providers if p not in PROVIDERS]
    if unknown:
        sys.exit(f"Unknown provider(s): {', '.join(unknown)} "
                 f"(valid: {', '.join(PROVIDERS)})")

    print(f"[i] {len(candidates)} bucket candidates | "
          f"{len(takeover_hosts)} takeover hosts | providers: "
          f"{', '.join(providers)}")
    if candidates:
        print(f"{_C.D}[i] Top candidates: "
              + ", ".join(n for n, *_ in candidates[:20]) + f"{_C.X}")
    est = len(takeover_hosts) + len(candidates) * len(providers)
    print(f"[i] Estimated storage requests: ~{est}")

    if args.dry_run:
        print(f"{_C.Y}[dry-run] no storage requests made. Re-run without "
              f"--dry-run to check {est} targets.{_C.X}")
        with open(args.out + ".candidates.txt", "w", encoding="utf-8") as fh:
            for n, spec, score, kind in candidates:
                fh.write(f"{n}\t{spec}\t{score}\t{kind}\n")
        print(f"[i] Candidate plan written to {args.out}.candidates.txt")
        return

    opts = Options(timeout=args.timeout, deep=args.deep, deep_config=args.deep,
                   check_write=args.check_write, delay=args.rate_delay,
                   workers=args.workers)
    if args.check_write:
        print(f"{_C.R}{_C.BOLD}[!] --check-write enabled: an anonymous PUT will "
              f"be attempted against buckets already classified org-owned and "
              f"public, then deleted. Proceed only with explicit program "
              f"authorization.{_C.X}")

    jsonl_path = args.out + ".stream.jsonl"
    resume_done = load_resume(jsonl_path) if args.resume else set()

    findings = run(candidates, takeover_hosts, providers, ctx, opts,
                   jsonl_path=jsonl_path, resume_done=resume_done,
                   show_all=args.show_all, only_confirmed=args.only_confirmed)

    groups = write_report(findings, program, args.out, scope_lines)

    n_pub = sum(len(groups[k]) for k in ("confirmed", "likely", "possible",
                                         "unverified", "public_unverified"))
    print(f"\n{_C.BOLD}[done]{_C.X} {len(findings)} checks | public-listable: "
          f"{n_pub} | org-confirmed: {len(groups['confirmed'])} | "
          f"org-likely: {len(groups['likely'])} | "
          f"config-exposure: {len(groups['config_only'])} | "
          f"takeover candidates: {len(groups['takeover'])}")

    for label, items in (("CONFIRMED org bucket", groups["confirmed"]),
                         ("LIKELY org bucket", groups["likely"]),
                         ("TAKEOVER candidate", groups["takeover"])):
        for f in items:
            print(f"  {_C.R}*{_C.X} [{label}] {f['target']} "
                  f"({f['provider']}, {f.get('severity')}, "
                  f"score={f.get('score', '-')})")

    print(f"[report] {args.out}.md | {args.out}.json | {args.out}.csv | "
          f"{jsonl_path}")
    if groups["confirmed"] or groups["likely"] or groups["takeover"]:
        print(f"{_C.Y}[next] Capture the exact request/response evidence for "
              f"each confirmed item, then STOP. Do not download real data and "
              f"do not claim takeover resources. Report against the program's "
              f"severity chart.{_C.X}")


if __name__ == "__main__":
    main()
