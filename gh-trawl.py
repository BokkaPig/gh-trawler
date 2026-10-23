#!/usr/bin/env python3
"""
Trawl GitHub repos for shipped default credentials in env/config files.

Usage:
  GITHUB_TOKEN=ghp_xxx ./gh-trawl.py --top 200 --min-stars 5000 -o results.jsonl
  GITHUB_TOKEN=ghp_xxx ./gh-trawl.py --top 1000 -o batch1.jsonl
  GITHUB_TOKEN=ghp_xxx ./gh-trawl.py --top 1000 --offset 1000 -o batch2.jsonl
  GITHUB_TOKEN=ghp_xxx ./gh-trawl.py --dump-keys keys.txt       # edit, then --keys keys.txt

Writes one JSONL record per finding, a TSV of every repo checked, and
hydra/ffuf-ready wordlists ranked by how many distinct repos ship the same
value. Pure template markers (${VAR}, <your-key-here>, {{ ... }}) are dropped;
usable weak literals (admin, changeme, password) are kept -- those are the point.
"""
import argparse, base64, json, math, os, re, sys, threading, time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
TOKEN = ""

# Self-hostable apps whose compose/env files ship working defaults. Stars alone
# surface libraries; these are what actually turns up unchanged on an engagement.
SEED_REPOS = """
grafana/grafana keycloak/keycloak minio/minio apache/airflow n8n-io/n8n
zabbix/zabbix nextcloud/docker gitlabhq/gitlabhq sonarsource/sonarqube
jenkinsci/docker rabbitmq/rabbitmq-server elastic/elasticsearch
influxdata/influxdb redis/redis postgres/postgres docker-library/mysql
mongodb/mongo apache/kafka apache/superset metabase/metabase
getsentry/self-hosted matrix-org/synapse mastodon/mastodon discourse/discourse
nocodb/nocodb appwrite/appwrite supabase/supabase directus/directus
strapi/strapi TryGhost/Ghost wordpress/wordpress magento/magento2
odoo/odoo frappe/frappe netbox-community/netbox zammad/zammad
mailcow/mailcow-dockerized docker-mailserver/docker-mailserver
portainer/portainer rancher/rancher goharbor/harbor
hashicorp/vault opf/openproject mattermost/mattermost
rocketchat/rocket.chat jitsi/docker-jitsi-meet pi-hole/docker-pi-hole
home-assistant/core gogs/gogs go-gitea/gitea apache/guacamole-server
thingsboard/thingsboard openhab/openhab-docker osticket/osTicket
glpi-project/glpi pydio/cells haiwen/seafile owncloud-docker/server
""".split()

CANDIDATE_PATH = re.compile(
    r"(^|/)("
    r"\.env[^/]*|[^/]*\.env|"
    r"docker-compose[^/]*\.ya?ml|compose[^/]*\.ya?ml|Dockerfile[^/]*|"
    r"config[^/]*\.(ya?ml|json|toml|ini|cfg|conf)|"
    r"settings[^/]*\.(py|ya?ml|json|ini)|"
    r"application[^/]*\.(properties|ya?ml)|"
    r"(?!messages)[^/]*(?<!_[a-z]{2})\.properties|"
    r"secrets?[^/]*\.(ya?ml|json|env)|credentials?|"
    r"appsettings[^/]*\.json|web\.config|"
    r"values[^/]*\.ya?ml|[^/]*\.tfvars|terraform\.tfvars[^/]*|"
    r"wp-config[^/]*\.php|local[_.-]?settings[^/]*\.py|"
    r"[^/]*\.(ini|cfg|conf)"
    r")$", re.I)
SKIP_PATH = re.compile(
    r"(^|/)(node_modules|vendor|third_party|testdata|test|tests|spec|specs|"
    r"fixtures|__tests__|__mocks__|benchmark|benchmarks|e2e|cypress|"
    r"l10n|lang|langs|messages|theme|themes|"
    r"__pycache__|\.git|dist|build|locale|i18n|translations)/", re.I)

# Key-name patterns. Dump with --dump-keys, edit, feed back with --keys.
SECRET_KEYS = [
    r"secret", r"api[_-]?key", r"access[_-]?key", r"passw(or)?d", r"passwd",
    r"(?<![a-z])pass(?![a-z])", r"pwd", r"jwt", r"token", r"private[_-]?key",
    r"salt", r"encryption", r"credential", r"client[_-]?secret",
    r"auth[_-]?(token|secret|key|pass|code)", r"(?<![a-z])pin(?![a-z])",
    r"root[_-]?pw", r"bootstrap[_-]?pass",
]
USER_KEYS = [
    r"(^|[_.\-])(user(name)?|login|account|admin)([_.\-]|$)",
    r"(^|[_.\-])root([_.\-](user|name|account))?$",
    r"admin[_-]?user", r"default[_-]?user", r"initial[_-]?admin",
]
SECRET_RE = re.compile("|".join(SECRET_KEYS), re.I)
USER_RE = re.compile("|".join(USER_KEYS), re.I)

# KEY=VALUE, KEY: VALUE, "KEY": "VALUE", - KEY = 'VALUE'
KV_RE = re.compile(r"""^\s*(?:-\s*)?(?:export\s+)?["']?(?P<k>[A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]\s*(?P<v>.+?)\s*,?$""")
DOCKER_ENV = re.compile(r"^\s*ENV\s+(?P<k>[A-Za-z_][\w.\-]*)[\s=]+(?P<v>.+?)\s*$", re.I)
URL_CRED = re.compile(r"""[a-z][a-z0-9+.\-]*://(?P<u>[^:/@\s"'<>]{1,64}):(?P<p>[^@/\s"'<>]{1,128})@""", re.I)
COMMENT = re.compile(r"^\s*(#|//|;|--|<!--|\*|/\*)")

# Substituted by machinery before the app ever sees them -- these can never be
# the live value, so they are the only thing worth discarding.
INTERPOLATED = re.compile(
    r"^(?:$|\$.*|.*\$\{.*|\{\{.*\}\}|%\(.*\)s|<%.*%>|"
    r"none|null|nil|n/?a|true|false|~|"
    r"[|>][+-]?|\[\s*\]|\{\s*\}|\d{1,3})$", re.I)

# Prose a developer was told to replace and often does not. NOT noise: these
# ship to production intact, and a left-in-place signing key is forgeable.
PLACEHOLDER = re.compile(
    r"^(?:<[^>]*>|your[_-].*|xxx+|\.{3,}|\*{3,}|todo|tbd|"
    r"replace.*|insert.*|change[_-]?(me|this|it|in|to).*|set[_-]?(me|this).*|"
    r"placeholder|redacted|dummy|sample|some|something|anything|whatever|"
    r"(a|an|the)[_-].*|.*[_-]from[_-].*|.*replace[_-]?me.*|"
    r".*(in|for)[_-]production.*|.*must[_-]be[_-].*|.*should[_-]be[_-].*)$"
    r"|(_here|_goes_here|_placeholder|_dashboard|_console|_portal|_value)$", re.I)

# Three or more lowercase words joined by _ or - reads as prose, not a secret.
WORDY = re.compile(r"^[a-z][a-z0-9]*([_-][a-z0-9]+){2,}$")

# DBUser / adminUser / dbPassword never matched the separator-anchored key
# patterns below. Split camelCase into snake_case first so one pattern set
# covers env vars, .properties and Java/.NET-style config alike.
CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def norm_key(k):
    return CAMEL.sub("_", k).lower()


# Dotted all-lowercase keys are i18n message paths (my_account.reset_password.page),
# not configuration. Two segments stay -- system.secret-key is a real setting.
I18N_KEY = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+){2,}$")
# A value that is a class name or an ALL_CAPS variable is a reference, not a secret.
# Both patterns deliberately spare Password123 / ChangeMe123.
IDENTIFIER = re.compile(r"^[A-Z][a-z]+([A-Z][a-z]+){2,}$|^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$")

# "AI21_MODEL_LIST=" left behind when one line held several pairs. Anchored to
# env-var shape -- ALL CAPS with an underscore -- because a looser rule eats
# base64 secrets, whose single "=" of padding looks identical.
BARE_KEY = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+=$")
# A wrapped value yields two candidates: a deployer may leave <secret> as-is,
# or the author may have meant the bare word. Spray both.
WRAPPED = re.compile(r"""^(?P<o>[<\[{("'])(?P<inner>.+)(?P<c>[>\]})"'])$""")

# Source code mis-parsed as a config value, and keys holding a path or a toggle.
CODEY = re.compile(r"[;()\[\]]|=>|\?\?|\s-{1,2}\w|process\.env|\.env\.|^\w+\.\w+$")
NOISE_KEY = re.compile(r"(_|^)(file|path|dir|folder|location|enabled|type|mode|algorithm|"
                       r"url|uri|endpoint|host|port|interval|timeout|minutes|seconds|parameter|param|command|cmd|script|args|class|method|tokens)$", re.I)

CLASSES = ("interpolated", "placeholder_default", "weak_default",
           "medium_default", "high_entropy_default", "identity")
DEFAULT_CLASSES = [c for c in CLASSES if c != "interpolated"]
_tls = threading.local()
_clear = threading.Event(); _clear.set()   # cleared while a thread sleeps off a rate limit
_rl_lock = threading.Lock()
_out_lock = threading.Lock()
_seen_lock = threading.Lock()
_seen = set()                              # dedupe keys, scope set by --dedupe


def sess(auth=True):
    """Thread-local sessions; the raw.githubusercontent one never sees the token."""
    key = "api" if auth else "raw"
    s = getattr(_tls, key, None)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": "gh-trawl"})
        if auth:
            s.headers.update({"Accept": "application/vnd.github+json",
                              "Authorization": f"Bearer {TOKEN}"})
        setattr(_tls, key, s)
    return s


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in c.values())


def dump_keys(path):
    with open(path, "w") as fh:
        fh.write("# gh-trawl key patterns -- Python regex, matched against the key name,\n"
                 "# case-insensitive. Default section is secret; prefix a line with\n"
                 "# 'user:' for identity keys. Feed back with --keys <file>.\n\n")
        fh.write("".join(p + "\n" for p in SECRET_KEYS))
        fh.write("\n")
        fh.write("".join("user: " + p + "\n" for p in USER_KEYS))


def load_keys(path, replace):
    """Read a --keys file into SECRET_RE / USER_RE, extending the built-ins unless
    --keys-only. A bad pattern names its own line rather than blowing up mid-scan."""
    global SECRET_RE, USER_RE
    sec, usr = [], []
    with open(path) as fh:
        for n, line in enumerate(fh, 1):
            line = line.split("#")[0].strip()
            if not line:
                continue
            low = line.lower()
            if low.startswith("user:"):
                bucket, pat = usr, line[5:].strip()
            elif low.startswith("secret:"):
                bucket, pat = sec, line[7:].strip()
            else:
                bucket, pat = sec, line
            try:
                re.compile(pat)
            except re.error as e:
                sys.exit(f"{path}:{n}: bad pattern {pat!r}: {e}")
            bucket.append(pat)
    if not replace:                     # a dumped file fed back must not double up
        sec = list(dict.fromkeys(SECRET_KEYS + sec))
        usr = list(dict.fromkeys(USER_KEYS + usr))
    if not sec and not usr:
        sys.exit(f"{path}: no patterns loaded")
    SECRET_RE = re.compile("|".join(sec), re.I) if sec else re.compile(r"(?!)")
    USER_RE = re.compile("|".join(usr), re.I) if usr else re.compile(r"(?!)")
    return len(sec), len(usr)


def _limited(r):
    return (r.headers.get("X-RateLimit-Remaining") == "0"
            or "Retry-After" in r.headers
            or "rate limit" in r.text.lower())


def _backoff(r):
    if not _rl_lock.acquire(blocking=False):
        _clear.wait()                       # someone else is already sleeping it off
        return
    try:
        _clear.clear()
        wait = float(r.headers.get("Retry-After", 0) or 0) or \
            max(int(r.headers.get("X-RateLimit-Reset", time.time() + 60)) - time.time(), 5)
        wait = min(wait, 900)
        print(f"[rate-limit] sleeping {wait:.0f}s", file=sys.stderr)
        time.sleep(wait)
    finally:
        _clear.set()
        _rl_lock.release()


def gh(url, **params):
    for _ in range(8):
        _clear.wait()
        r = sess().get(url, params=params, timeout=30)
        if r.status_code in (403, 429) and _limited(r):
            _backoff(r)
            continue
        if r.status_code in (404, 409, 451, 422):   # gone, empty, DMCA, past search cap
            return None
        r.raise_for_status()
        return r
    return None


def top_repos(n, min_stars, offset=0):
    """Descending star order, offset-aware. GitHub stops paginating at 1000
    results, so past that we re-query with a shrinking stars:<=ceiling window."""
    want, out, seen, ceiling = offset + n, [], set(), None
    while len(out) < want:
        q = f"stars:>{min_stars}" if ceiling is None else f"stars:{min_stars + 1}..{ceiling}"
        page, added = 1, 0
        while len(out) < want and page <= 10:
            r = gh(f"{API}/search/repositories", q=q, sort="stars",
                   order="desc", per_page=100, page=page)
            if r is None:
                break
            items = r.json().get("items", [])
            if not items:
                break
            for it in items:
                if it["full_name"] in seen:
                    continue
                seen.add(it["full_name"])
                out.append(it)
                added += 1
            page += 1
            time.sleep(2.1)                          # search API: 30 req/min
        if added == 0:
            break
        low = out[-1]["stargazers_count"]
        if ceiling is not None and low >= ceiling:   # whole window was one star value
            low = ceiling - 1
        ceiling = low
        if ceiling <= min_stars:
            break
        if len(out) < want:
            print(f"[search] {len(out)}/{want} repos, window now stars<={ceiling}", file=sys.stderr)
    return out[offset:want]


def seed_repos(names):
    out = []
    for name in names:
        r = gh(f"{API}/repos/{name}")
        if r:
            out.append(r.json())
        else:
            print(f"[skip] {name} not found", file=sys.stderr)
    return out


def priority(p):
    pl = p.lower()
    if re.search(r"\.env|docker-compose|compose\.ya?ml", pl):
        return 3
    if re.search(r"appsettings|wp-config|values\.ya?ml|\.properties|\.tfvars|secret", pl):
        return 2
    return 1


def walk(repo, depth=4, budget=400):
    """Fallback when the recursive tree comes back truncated."""
    out, queue, calls = [], [("", repo["default_branch"])], 0
    while queue and calls < budget:
        path, sha = queue.pop(0)
        r = gh(f"{API}/repos/{repo['full_name']}/git/trees/{sha}")
        calls += 1
        if not r:
            continue
        for t in r.json().get("tree", []):
            p = f"{path}/{t['path']}" if path else t["path"]
            if t["type"] == "blob":
                out.append(p)
            elif t["type"] == "tree" and p.count("/") < depth and not SKIP_PATH.search(p + "/"):
                queue.append((p, t["sha"]))
    return out


def candidate_files(repo, cap, deep=False):
    """Returns (paths, truncated). A truncated tree still hands back tens of
    thousands of paths -- far better coverage than re-walking it one directory
    per request, so the partial list is used unless --deep-walk is given."""
    r = gh(f"{API}/repos/{repo['full_name']}/git/trees/{repo['default_branch']}", recursive=1)
    if not r:
        return [], False
    j = r.json()
    truncated = bool(j.get("truncated"))
    paths = [t["path"] for t in j.get("tree", []) if t["type"] == "blob"]
    if truncated and deep:
        paths = walk(repo)
    paths = [p for p in paths if CANDIDATE_PATH.search(p) and not SKIP_PATH.search(p)]
    paths.sort(key=lambda p: (-priority(p), len(p)))
    return paths[:cap], truncated


def fetch_raw(repo, path):
    url = f"{RAW}/{repo['full_name']}/{repo['default_branch']}/{path}"
    try:
        r = sess(auth=False).get(url, timeout=30)
    except requests.RequestException:
        return ""
    return r.text if r.ok and len(r.content) < 512_000 else ""


def extract(text, depth=0):
    """Yield (line_no, key, value, kind) where kind is secret | user."""
    for ln, line in enumerate(text.splitlines(), 1):
        if COMMENT.match(line):
            continue
        for m in URL_CRED.finditer(line):       # postgres://user:pass@host
            yield ln, "URL[user]", m["u"], "user"
            yield ln, "URL[pass]", m["p"], "secret"
        m = DOCKER_ENV.match(line) or KV_RE.match(line)
        if not m:
            continue
        k = m["k"]
        nk = norm_key(k)
        if NOISE_KEY.search(nk) or I18N_KEY.match(nk):
            continue
        kind = "secret" if SECRET_RE.search(nk) else "user" if USER_RE.search(nk) else None
        if not kind:
            continue
        v = m["v"].split(" #")[0].strip().rstrip("\\").strip().strip("\"'`")
        # KV_RE runs to end of line, so "api_key: str | None = None" and lines
        # carrying several pairs over-capture. The real value follows the last
        # "="; base64 padding has no whitespace, so it is never touched.
        if "=" in v and any(c.isspace() for c in v):
            v = v.rsplit("=", 1)[1].strip().strip("\"'`")
        if BARE_KEY.match(v):
            continue
        if CODEY.search(v) or IDENTIFIER.match(v) or v[:1] == "#" or v[:2] == "//":
            continue
        yield ln, k, v, kind
        if depth == 0:                      # one level of base64 only
            for k2, v2, kind2 in decoded_pairs(k, v):
                yield ln, k2, v2, kind2


B64 = re.compile(r"^[A-Za-z0-9+/]{16,4096}={0,2}$")


def b64_decode(v):
    """Decoded text, if v is base64 that unpacks to printable ASCII. Secrets are
    routinely shipped base64-encoded, and the plaintext inside is the finding."""
    if not B64.match(v):
        return None
    try:
        raw = base64.b64decode(v + "=" * (-len(v) % 4), validate=True)
        s = raw.decode("ascii")
    except Exception:
        return None
    if len(s) < 8 or not all(c.isprintable() or c in "\n\t" for c in s):
        return None
    return s


def _walk_json(obj, prefix=""):
    if isinstance(obj, dict):
        for k, val in obj.items():
            yield from _walk_json(val, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_json(item, prefix)
    elif obj is not None and prefix:
        yield prefix, str(obj)


def decoded_pairs(key, v):
    """Yield (key, value, kind) found inside a base64 value: the plaintext
    itself, or the credentials nested in a JSON blob."""
    s = b64_decode(v)
    if s is None:
        return
    flat = s.strip()
    if flat[:1] in "{[":
        try:
            for k2, v2 in _walk_json(json.loads(flat)):
                nk = norm_key(k2.rsplit(".", 1)[-1])
                kind = "secret" if SECRET_RE.search(nk) else "user" if USER_RE.search(nk) else None
                if kind and v2 and not CODEY.search(v2):
                    yield f"{key}[b64].{k2}", v2, kind
            return
        except (json.JSONDecodeError, ValueError):
            pass
    if "\n" in flat:                       # a decoded config file: re-extract it
        for _, k2, v2, kind2 in extract(flat, depth=1):
            yield f"{key}[b64].{k2}", v2, kind2
        return
    nk = norm_key(key)
    kind = "secret" if SECRET_RE.search(nk) else "user" if USER_RE.search(nk) else None
    if kind and not CODEY.search(flat):
        yield f"{key}[b64]", flat, kind


def classify(v, kind):
    if INTERPOLATED.match(v):
        return "interpolated"
    if kind == "user":
        return "identity"
    if PLACEHOLDER.match(v) or (WORDY.match(v) and len(v) >= 12):
        return "placeholder_default"    # shipped-as-is prose -> still a finding
    e = entropy(v)
    if len(v) >= 16 and e >= 3.5 and not WORDY.match(v):
        return "high_entropy_default"   # looks real, shipped in repo -> most dangerous
    if len(v) < 8 or e < 2.5:
        return "weak_default"
    return "medium_default"


def dedupe_key(rec, mode):
    if mode == "file":
        return (rec["repo"], rec["path"], rec["key"], rec["value"])
    if mode == "repo":
        return (rec["repo"], rec["key"], rec["value"])
    if mode == "value":
        return (rec["kind"], rec["value"])
    return (rec["kind"], rec["key"], rec["value"])      # global


def keep(rec, mode):
    if mode == "none":
        return True
    k = dedupe_key(rec, mode)
    with _seen_lock:
        if k in _seen:
            return False
        _seen.add(k)
        return True


def scan(repo, cap, classes, deep=False):
    recs, err = [], ""
    try:
        paths, truncated = candidate_files(repo, cap, deep)
    except Exception as e:
        return repo, [], 0, False, f"tree: {e}"
    for p in paths:
        try:
            txt = fetch_raw(repo, p)
        except Exception as e:
            err = f"raw {p}: {e}"
            continue
        if not txt:
            continue
        for ln, k, v, kind in extract(txt):
            cls = classify(v, kind)
            if cls not in classes:
                continue
            recs.append({"repo": repo["full_name"], "stars": repo.get("stargazers_count", 0),
                         "path": p, "line": ln, "key": k, "value": v, "kind": kind,
                         "entropy": round(entropy(v), 2), "class": cls})
    return repo, recs, len(paths), truncated, err


TEMPLATE_FRAGMENT = re.compile(r"[{<][^{}<>]*[}>]")
PATHISH = re.compile(r"""^["'<\[({]?(~|\.{1,2})?/""")
URLISH = re.compile(r"://")


def variants(v):
    """The value plus, if it is wrapped, its unwrapped form."""
    out = [v]
    m = WRAPPED.match(v)
    if m:
        inner = m["inner"].strip().strip("\"'`")
        if inner and inner != v:
            out.append(inner)
    return out


def usable(v, min_len=4):
    """(ok, reason). A wordlist entry has to be sprayable exactly as written.
    Character checks run before the length ones so a short non-ASCII string is
    reported as non-ascii -- the reason is what you review excluded.tsv by."""
    if not v:
        return False, "empty"
    if not v.isascii():
        return False, "non-ascii"          # translated UI strings, not credentials
    if not v.isprintable():
        return False, "control-chars"
    if any(c.isspace() for c in v):
        return False, "whitespace"         # UI text and type annotations
    if not any(c.isalnum() for c in v):
        return False, "no-alnum"           # bare "{", "~", structural leftovers
    if PATHISH.match(v):
        return False, "path"               # ~/build, ./conf, </mail_crypt/key.pem
    if URLISH.search(v):
        return False, "url"                # endpoints, not credentials
    if '"' in v:
        return False, "json-fragment"      # {"data":{"token":"..."}}
    if not WRAPPED.match(v) and TEMPLATE_FRAGMENT.search(v):
        return False, "template-fragment"  # {env}WEBDAV_PASSWORD, v1,whsec_<x>
    if len(v) < min_len:
        return False, "too-short"
    if len(v) > 128:
        return False, "too-long"
    return True, ""


def wordlists(jsonl, outdir, min_len=4):
    """Rank by distinct repos: the same value in many repos is a shipped default."""
    os.makedirs(outdir, exist_ok=True)
    users, passes = defaultdict(set), defaultdict(set)
    keys, cls_of = defaultdict(Counter), {}
    per_file = defaultdict(lambda: {"user": set(), "secret": set()})
    rejects = defaultdict(set)
    with open(jsonl) as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            bucket = users if rec["kind"] == "user" else passes
            for v in variants(rec["value"]):
                ok, why = usable(v, min_len)
                if not ok:
                    rejects[why].add(v)
                    continue
                bucket[v].add(rec["repo"])
                keys[(rec["kind"], v)][rec["key"]] += 1
                cls_of[(rec["kind"], v)] = rec["class"]
                per_file[(rec["repo"], rec["path"])][rec["kind"]].add(v)

    def dump(name, d):
        rows = sorted(d.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        with open(os.path.join(outdir, name), "w") as fh:
            fh.write("".join(v + "\n" for v, _ in rows))
        return rows

    urows = dump("users.txt", users)
    prows = dump("passwords.txt", passes)
    # Left-in-place prose, on its own list -- a shipped signing key is forgeable,
    # so these are usually worth trying before any guessable password.
    ph = {v: r for v, r in passes.items() if cls_of.get(("secret", v)) == "placeholder_default"}
    phrows = dump("placeholders.txt", ph)

    combos = set()
    for d in per_file.values():
        if len(d["user"]) * len(d["secret"]) > 64:   # don't explode on grab-bag config files
            continue
        for u in d["user"]:
            for p in d["secret"]:
                if ":" in u or ":" in p:    # hydra -C splits on the first colon
                    continue
                combos.add(f"{u}:{p}")
    with open(os.path.join(outdir, "combos.txt"), "w") as fh:
        fh.write("".join(c + "\n" for c in sorted(combos)))

    with open(os.path.join(outdir, "excluded.tsv"), "w") as fh:
        fh.write("reason\tvalue\n")
        for why in sorted(rejects):
            for v in sorted(rejects[why]):
                fh.write(f"{why}\t{v}\n")

    with open(os.path.join(outdir, "defaults.tsv"), "w") as fh:
        fh.write("repos\tkind\tclass\tvalue\ttop_key\n")
        for kind, rows in (("user", urows), ("secret", prows)):
            for v, repos in rows:
                fh.write(f"{len(repos)}\t{kind}\t{cls_of.get((kind, v), '')}\t{v}\t"
                         f"{keys[(kind, v)].most_common(1)[0][0]}\n")
    return len(urows), len(prows), len(combos), len(phrows), sum(len(s) for s in rejects.values())


def load_done(repos_out, jsonl):
    """Repos already checked. The TSV is authoritative -- it records repos that
    produced zero findings, which the JSONL cannot."""
    done = set()
    if os.path.exists(repos_out):
        with open(repos_out) as fh:
            for line in fh:
                name = line.split("\t")[0].strip()
                if name and name != "repo":
                    done.add(name)
    if os.path.exists(jsonl):
        with open(jsonl) as fh:
            for line in fh:
                try:
                    done.add(json.loads(line)["repo"])
                except (json.JSONDecodeError, KeyError):
                    pass
    return done


def preload_seen(jsonl, mode):
    if mode == "none" or not os.path.exists(jsonl):
        return
    with open(jsonl) as fh:
        for line in fh:
            try:
                _seen.add(dedupe_key(json.loads(line), mode))
            except (json.JSONDecodeError, KeyError):
                pass


def main():
    global TOKEN
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=100, help="starred repos to scan (0 to skip)")
    ap.add_argument("--offset", type=int, default=0,
                    help="skip this many top-starred repos first (e.g. --offset 1000 --top 1000)")
    ap.add_argument("--min-stars", type=int, default=5000)
    ap.add_argument("--seeds", help="file of owner/repo lines; defaults to built-in self-hosted app list")
    ap.add_argument("--no-seeds", action="store_true")
    ap.add_argument("--keys", help="file of key-name patterns to look for")
    ap.add_argument("--keys-only", action="store_true", help="--keys replaces the built-ins instead of extending")
    ap.add_argument("--dump-keys", metavar="FILE", help="write the built-in key patterns and exit")
    ap.add_argument("--dedupe", choices=["none", "file", "repo", "global", "value"], default="repo",
                    help="drop repeat findings: file=same file, repo=same repo (default), "
                         "global=same key+value anywhere, value=same value anywhere")
    ap.add_argument("--classes", default=",".join(DEFAULT_CLASSES),
                    help="comma list of classes to emit, or 'all'. Known: " + ", ".join(CLASSES)
                         + ". Default omits only 'interpolated' (${VAR}, {{x}}, empty).")
    ap.add_argument("--min-length", type=int, default=4,
                    help="drop wordlist entries shorter than this (default 4). Raising it "
                         "to 8 removes admin/root/guest/123456 -- the most widely shipped "
                         "defaults. Findings stay in the JSONL either way.")
    ap.add_argument("--max-files", type=int, default=40, help="candidate files per repo")
    ap.add_argument("--deep-walk", action="store_true",
                    help="on a truncated tree, re-walk directory by directory (slow: "
                         "minutes per repo). Default uses the partial tree and flags it.")
    ap.add_argument("-t", "--threads", type=int, default=8)
    ap.add_argument("-o", "--out", default="results.jsonl")
    ap.add_argument("-r", "--repos-out", default="repos-checked.tsv", help="log of every repo scanned")
    ap.add_argument("-w", "--wordlist-dir", default="wordlists")
    ap.add_argument("--resume", action="store_true", help="append, skipping repos already checked")
    ap.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args()

    if a.dump_keys:
        dump_keys(a.dump_keys)
        print(f"[keys] {len(SECRET_KEYS)} secret + {len(USER_KEYS)} user patterns -> {a.dump_keys}",
              file=sys.stderr)
        return

    TOKEN = os.environ.get("GITHUB_TOKEN", "")
    if not TOKEN:
        sys.exit("Set GITHUB_TOKEN (unauthenticated limit is 60 req/hr)")
    classes = set(CLASSES) if a.classes.strip().lower() == "all" else \
        {c.strip() for c in a.classes.split(",") if c.strip()}
    unknown = classes - set(CLASSES)
    if unknown:
        sys.exit(f"--classes: unknown {', '.join(sorted(unknown))}; known: {', '.join(CLASSES)}")
    if a.keys:
        s, u = load_keys(a.keys, a.keys_only)
        print(f"[keys] {s} secret + {u} user patterns from {a.keys}", file=sys.stderr)

    done = set()
    if a.resume:
        done = load_done(a.repos_out, a.out)
        preload_seen(a.out, a.dedupe)
        print(f"[resume] {len(done)} repos already checked, {len(_seen)} values known",
              file=sys.stderr)

    repos = []
    if not a.no_seeds:
        names = SEED_REPOS
        if a.seeds:
            with open(a.seeds) as fh:
                names = [l.split("#")[0].strip() for l in fh]
                names = [n for n in names if n]
        repos += seed_repos(names)
    if a.top:
        repos += top_repos(a.top, a.min_stars, a.offset)

    queue, seen = [], set()
    for r in repos:                              # seeds first, dedup, skip resumed
        n = r["full_name"]
        if n in seen or n in done:
            continue
        seen.add(n)
        queue.append(r)
    print(f"[plan] {len(queue)} repos, {a.threads} threads, dedupe={a.dedupe}, "
          f"classes={','.join(sorted(classes))}", file=sys.stderr)

    new_log = not (a.resume and os.path.exists(a.repos_out))
    hits = dropped = 0
    with open(a.out, "a" if a.resume else "w") as fh, \
            open(a.repos_out, "a" if a.resume else "w") as rf, \
            ThreadPoolExecutor(max_workers=a.threads) as pool:
        if new_log:
            rf.write("repo\tstars\tbranch\tfiles\thits\ttruncated\terror\n")
        futs = {pool.submit(scan, r, a.max_files, classes, a.deep_walk): r for r in queue}
        for fut in as_completed(futs):
            repo = futs[fut]
            try:
                repo, recs, nfiles, truncated, err = fut.result()
            except Exception as e:               # one bad repo shouldn't kill the run
                recs, nfiles, truncated, err = [], 0, False, str(e)
            kept = 0
            with _out_lock:
                for rec in recs:
                    if not keep(rec, a.dedupe):
                        dropped += 1
                        continue
                    fh.write(json.dumps(rec) + "\n")
                    hits += 1
                    kept += 1
                    if not a.quiet and rec["class"] != "identity":
                        print(f"{rec['class']:22} {rec['repo']}:{rec['path']}:{rec['line']}"
                              f"  {rec['key']}={rec['value'][:40]}")
                fh.flush()
                rf.write(f"{repo['full_name']}\t{repo.get('stargazers_count', 0)}\t"
                         f"{repo.get('default_branch', '')}\t{nfiles}\t{kept}\t"
                         f"{int(truncated)}\t{err}\n")
                rf.flush()
            if err:
                print(f"[error] {repo['full_name']}: {err}", file=sys.stderr)
            elif not a.quiet:
                print(f"[done] {repo['full_name']} ({nfiles} files, {kept} hits)", file=sys.stderr)

    if a.wordlist_dir:
        u, p, c, ph, ex = wordlists(a.out, a.wordlist_dir, a.min_length)
        print(f"[wordlists] {u} users, {p} passwords ({ph} left-in-place placeholders), "
              f"{c} combos, {ex} excluded -> {a.wordlist_dir}/", file=sys.stderr)
    print(f"[total] {hits} findings ({dropped} deduped) -> {a.out}; "
          f"repo log -> {a.repos_out}", file=sys.stderr)


if __name__ == "__main__":
    main()
