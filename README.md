# gh-trawl

Trawls public GitHub repositories for credentials that ship inside config files —
default passwords, left-in-place placeholders, and hardcoded secrets — and turns
them into ranked wordlists for credential testing.

The premise: vendors ship a working default (`minioadmin`, `rootpass`) or a
prompt the deployer is meant to replace (`CHANGE-ME-IN-PRODUCTION`). Plenty of
deployments never change either. This builds the list of what to try.

**Scope note.** This reads public repositories only. Finding `grafana12345` in
Grafana's repo tells you what to *try* against a target — confirming it still
works there is a separate, authorised activity.

---

## Repo layout

| File | Purpose |
|---|---|
| `gh-trawl.py` | The tool. Single file, no package layout. |
| `test_gh_trawl.py` | Regression suite — `python3 test_gh_trawl.py`, 30 tests, no network or token needed. |
| `AGENTS.md` | Architecture, invariants and gotchas for anyone (or anything) editing the tool. |
| `seeds.example.txt` | The built-in seed list, editable — use with `--seeds`. |
| `keys.example.txt` | The built-in key patterns, editable — use with `--keys`. |

---

## Setup

Requires Python 3.8+ and `requests`:

```bash
pip install requests          # or: sudo apt install python3-requests
python3 test_gh_trawl.py      # confirm the install works; needs no token
```

### GitHub token

Unauthenticated you get 60 requests/hour, which is useless. A token raises that
to 5,000/hour.

1. github.com → avatar → **Settings** → **Developer settings**
2. **Personal access tokens** → **Tokens (classic)** → **Generate new token (classic)**
   (direct link: <https://github.com/settings/tokens/new>)
3. Name it, set an expiry, and **tick no scopes at all**.
4. Copy the `ghp_…` value.

Reading public repos needs **zero** permissions. An unscoped token gets the full
5,000/hr budget, so ticking `repo` would grant write access to all your private
repositories for no benefit. If you prefer a hard-scoped token, the fine-grained
flavour with *Repository access → Public Repositories (read-only)* and no account
permissions is equivalent.

Store it outside your shell history:

```bash
touch ~/.gh-trawl-token && chmod 600 ~/.gh-trawl-token
# paste the token into the file with an editor, rather than echo'ing it
GITHUB_TOKEN=$(cat ~/.gh-trawl-token) ./gh-trawl.py --top 100
```

Avoid `export GITHUB_TOKEN=` in `.zshrc` — it leaks into every process you run,
including anything pointed at a client network.

Verify it works:

```bash
curl -s -H "Authorization: Bearer $(cat ~/.gh-trawl-token)" \
  https://api.github.com/rate_limit | python3 -m json.tool | head -20
```

---

## Quick start

```bash
mkdir scan && cd scan
GITHUB_TOKEN=$(cat ~/.gh-trawl-token) python3 ../gh-trawl.py \
  --top 500 --min-stars 10000 -t 8 --resume \
  -o results.jsonl -r repos-checked.tsv -w wordlists
```

Roughly 5 minutes for ~550 repos. Leave `--resume` on permanently — it costs
nothing on a fresh run and means an interrupt never loses work.

---

## What it scans

Two sources, combined and deduplicated:

- **Seed repos** — 58 self-hostable applications baked in (Grafana, Keycloak,
  MinIO, Airflow, n8n, Zabbix, Nextcloud, Gitea, Mattermost…). These are where
  the defaults actually live. Override with `--seeds file.txt`, disable with
  `--no-seeds`.
- **Top-starred repos** — `--top N --min-stars S`. Mostly libraries, lower yield,
  but broad coverage.

Within each repo it pulls the file tree and fetches candidates: `.env*`,
`docker-compose*.yml`, `Dockerfile*`, `appsettings*.json`, `values*.yaml`,
`*.tfvars`, `wp-config.php`, `web.config`, `*.properties`, `*.ini/cfg/conf`,
`config*.{yml,json,toml}`, `settings*.py`. Test, vendor, i18n and theme
directories are skipped. Candidates are ranked (`.env` and compose first) and
capped per repo by `--max-files` (default 40).

Credentials are extracted from `KEY=VALUE`, `KEY: VALUE`, `"KEY": "VALUE"`,
Dockerfile `ENV` lines, and `user:pass@host` inside connection strings. Key names
are normalised from camelCase before matching, so `DBUser`, `adminUser` and
`APIKey` match the same patterns as `DB_USER`.

### base64

Secrets are routinely shipped base64-encoded, so any value that decodes to
printable ASCII is decoded and run back through the same extraction. Both forms
are kept — the encoded string is what sits in the config, the plaintext is what
the application uses.

- A plain secret yields `KEY[b64]` with the decoded value.
- A JSON blob is walked, so `{"UserID":"defaultUser","Password":"defaultPassword"}`
  becomes `KEY[b64].UserID` and `KEY[b64].Password`.
- A decoded config file is re-extracted line by line.

Decoding goes one level deep. Values that merely look like base64 (hex digests,
`AKIAIOSFODNN7EXAMPLE`) decode to non-text and are left alone.

---

## Classification

Every finding is labelled. The dividing line is **whether the string gets
substituted before the application ever reads it**:

| Class | Meaning | Example |
|---|---|---|
| `interpolated` | Replaced by machinery — can never be the live value. **Dropped by default.** | `${JWT_SECRET}`, `{{ .Values.pw }}`, `null`, `[]` |
| `placeholder_default` | Prose the deployer was told to replace, and often doesn't. | `CHANGE-ME-OR-FAIL-TO-START`, `your_api_key_here` |
| `weak_default` | Short or low-entropy literal. | `admin`, `guest`, `minioadmin` |
| `medium_default` | Ordinary literal. | `rootpass`, `Password123` |
| `high_entropy_default` | Long and random-looking — a real secret committed to the repo. | `8f4c1b9e2a7d6350af91c2e4b8d70516` |
| `identity` | A username rather than a secret. | `postgres`, `admin` |

`--classes` selects what gets written. Default is everything except
`interpolated`; `--classes all` includes those too.

```bash
./gh-trawl.py --classes placeholder_default --top 500   # triage one class
```

**On severity:** a left-in-place `SESSION_SECRET` or `JWT_SECRET` is not the same
as a guessable password. With the signing key you forge tokens offline — no login
attempt, no lockout, no failed-auth logging. Worth separating in a report from
"admin:admin still works". The `class` column in `defaults.tsv` gives you that
split.

---

## Output

| File | Contents |
|---|---|
| `results.jsonl` | One JSON record per finding: repo, path, line, key, value, kind, entropy, class. |
| `repos-checked.tsv` | Every repo scanned: stars, branch, candidate files, hits, truncated flag, error. Drives `--resume`. |
| `wordlists/passwords.txt` | Secrets, ranked by how many distinct repos ship them. |
| `wordlists/users.txt` | Usernames, same ranking. |
| `wordlists/combos.txt` | `user:pass` pairs seen in the same file — feed to `hydra -C`. |
| `wordlists/placeholders.txt` | Just the left-in-place prose. Usually worth trying first. |
| `wordlists/defaults.tsv` | Everything with repo count, class, and the most common key name. |
| `wordlists/excluded.tsv` | Every value filtered out of the wordlists, with the reason. Nothing is silently dropped. |

Wordlist entries have to be sprayable exactly as written. A value is excluded when
it is shorter than `--min-length` (default 4), longer than 128, non-ASCII
(translated UI strings — `密码`, `Пароль`), contains whitespace (UI text, type
annotations) or control characters, has no alphanumeric character at all (a bare
`{`), looks like a path (`~/build`, `/var/lib`) or a URL, or is a JSON or template
fragment (`{"data":{...}}`, `{env}WEBDAV_PASSWORD`). Everything excluded stays in
`results.jsonl` and is listed in `excluded.tsv` with its reason, so you can pull
any of it back.

**`--min-length` is the one worth tuning.** It defaults to 4, which keeps
`admin`, `root`, `guest`, `secret` and `123456` — the most widely shipped
defaults in the data. Raising it to 8 drops all of them:

| | users | passwords | combos |
|---|---|---|---|
| `--min-length 4` (default) | 981 | 1,888 | 1,832 |
| `--min-length 8` | 475 | 1,622 | 947 |

`combos.txt` additionally skips any pair where either half contains a colon,
since `hydra -C` splits on the first one.

A wrapped value produces **both** forms: `<secret>` yields `<secret>` and
`secret`, `{value}` yields `{value}` and `value`. A deployer may leave either.

Ranking matters: a value shipped by 20 repos is a near-certain default, one seen
once is probably specific to that project.

```bash
hydra -L wordlists/users.txt -P wordlists/passwords.txt <target> http-post-form ...
ffuf -w wordlists/passwords.txt ...
```

---

## Flags

```
--top N               starred repos to scan (0 to skip, seeds only)
--offset N            skip the first N starred repos (--offset 1000 --top 1000)
--min-stars S         star floor for the search (default 5000)
--seeds FILE          owner/repo per line, '#' comments; replaces the built-in list
--no-seeds            skip seeds entirely
--keys FILE           extra key-name patterns to match
--keys-only           --keys replaces the built-ins instead of extending them
--dump-keys FILE      write the built-in patterns out and exit
--classes LIST        comma list, or 'all' (default: all but 'interpolated')
--dedupe MODE         none | file | repo (default) | global | value
--min-length N        drop wordlist entries shorter than N (default 4)
--max-files N         candidate files per repo (default 40)
--deep-walk           re-walk truncated trees directory by directory (slow)
-t, --threads N       default 8
-o, --out FILE        findings JSONL (default results.jsonl)
-r, --repos-out FILE  repo log TSV (default repos-checked.tsv)
-w, --wordlist-dir D  wordlist output directory (default wordlists)
--resume              append, skipping repos already in the repo log
-q, --quiet           suppress the per-finding stream
```

### Custom key patterns

```bash
./gh-trawl.py --dump-keys keys.txt     # 18 secret + 5 user patterns, editable
# add your own, one Python regex per line; prefix with 'user:' for identity keys
./gh-trawl.py --keys keys.txt --top 200
```

Patterns extend the built-ins unless `--keys-only`. Each is compiled on load, so
a typo reports `keys.txt:7: bad pattern` rather than failing mid-scan.
Connection-string extraction runs independently of these patterns.

### Dedupe modes

`repo` (default) keeps one record per repo+key+value, which preserves the
repo-count ranking. **`global` and `value` flatten that ranking** — a value
shipped by 200 repos reports as 1 and sorts beside a one-off. Use those only when
you want a thin spray list and don't care about confidence.

### Paging past 1000

GitHub's search API stops at 1000 results. `--offset` beyond that re-queries with
a shrinking `stars:` window automatically:

```bash
./gh-trawl.py --top 1000 -o batch1.jsonl
./gh-trawl.py --top 1000 --offset 1000 -o batch2.jsonl
```

---

## Rate limits and performance

- **Core API: 5,000/hr.** One call per repo, so repo count is barely a constraint.
- **Search API: 30/min.** About one call per 100 repos.
- **Raw file fetches** go to `raw.githubusercontent.com` unauthenticated and don't
  touch the API limit. This is where the wall-clock time goes.

Measured: ~550 repos in about 5 minutes at `-t 8`. Backoff honours `Retry-After`
and `X-RateLimit-Reset`; when one thread sleeps off a limit the others block
rather than piling in.

---

## Known limits

- **`-t 8` is untuned.** It has not tripped backoff at 550 repos, so the ceiling
  is unknown. Drop to 4 if you see repeated `[rate-limit]` lines.
- **Throttling looks like clean code.** `fetch_raw` returns `""` on any non-OK
  response, so if raw.githubusercontent starts pushing back, repos log
  `N files, 0 hits` and read as having nothing. A sudden run of zero-hit rows
  after a productive stretch means throttling — lower `-t` and `--resume`.
- **Truncated trees.** Repos over ~100k files return a partial tree; those rows
  are flagged `truncated=1` in the repo log, meaning coverage was incomplete.
  `--deep-walk` re-walks properly but costs minutes per repo.
- **Line-based extraction.** Nested JSON/YAML structure is not parsed, so a value
  is matched against the nearest key on its own line.
- **Bare CamelCase values** such as `KafkaCredentials` can still register as
  findings. The rule that would catch them also catches `ChangeMe123`.
