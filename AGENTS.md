# AGENTS.md

Guidance for AI agents (and humans) working on `gh-trawl.py`.

## What this is

A pentest recon tool. It reads **public** GitHub repos, pulls credentials out of
shipped config files, and ranks them into wordlists for credential testing
against systems you are authorised to test. It does not authenticate anywhere
except `api.github.com`, and it never writes to a repo.

Single file, no package layout. `gh-trawl.py` is the whole tool;
`test_gh_trawl.py` is the regression suite.

## Run the tests before and after any change

```bash
python3 test_gh_trawl.py          # 30 tests, no network, no token
```

Every test there is a bug that actually shipped. **If a test fails after your
change, read its comment before touching the assertion.** Most of them guard a
filter that was once too greedy and silently deleted real findings — the failure
mode this tool is most prone to.

For anything touching network behaviour, a live smoke test:

```bash
GITHUB_TOKEN=$(cat ~/.gh-trawl-token) python3 gh-trawl.py \
  --no-seeds --top 5 --min-stars 50000 -t 2 -o /tmp/t.jsonl -r /tmp/t.tsv -w /tmp/tw
```

## The pipeline

Order matters; each stage can only discard what the previous one passed.

```
top_repos() / seed_repos()     which repos
  -> candidate_files()         CANDIDATE_PATH minus SKIP_PATH, ranked, capped
  -> fetch_raw()               raw.githubusercontent, unauthenticated
  -> extract()                 per line: COMMENT -> KV_RE/DOCKER_ENV/URL_CRED
                                 -> norm_key -> NOISE_KEY/I18N_KEY -> SECRET_RE/USER_RE
                                 -> value cleanup -> BARE_KEY/CODEY
                                 -> decoded_pairs() for base64
  -> classify()                interpolated | placeholder_default | weak | medium
                                 | high_entropy | identity
  -> keep()                    --dedupe scope
  -> results.jsonl             provenance: repo, path, line, key, value, class
  -> wordlists()               variants() -> usable() -> ranked .txt files
```

`results.jsonl` is the record of what was actually in the file. `wordlists/` is
the sprayable artifact. **Filter in `usable()`, not in `extract()`**, unless the
thing genuinely is not a credential — that way nothing is lost from the JSONL and
everything rejected lands in `excluded.tsv` with a reason.

## Invariants — do not break these

These each cost a real finding when they were broken:

1. **Short values are the best values.** `admin`, `root`, `guest`, `123456` are
   the most widely shipped defaults in the data. `--min-length` defaults to 4 for
   this reason. Do not raise the default.
2. **Base64 padding is not a leaked key.** `BARE_KEY` must stay anchored to
   env-var shape (`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+=$`). A looser rule matches
   `MDAwMDAw…=` and deletes real secrets.
3. **Placeholders are findings, not noise.** `changeme`,
   `CHANGE-ME-IN-PRODUCTION`, `your_api_key_here` ship to production intact. Only
   `interpolated` values — ones machinery substitutes before the app reads them —
   get discarded.
4. **Entropy does not mean random.** Shannon entropy counts distinct characters,
   so `client_secret_from_auth0_dashboard` scores higher than a real key. `WORDY`
   routes lower-snake prose to `placeholder_default` instead.
5. **Key matching runs on `norm_key(k)`**, never the raw key. `DBUser` must
   normalise to `db_user` or every Java/.NET/`.conf` key is invisible.
6. **`combos.txt` entries must not contain a colon** on either side — `hydra -C`
   splits on the first one, so a colon corrupts the pair.
7. **Braces are not automatically code.** `CODEY` holds `;()[]` only. Adding
   `{}` back kills `{value}` placeholders.

## Changing the filters

Both failure directions are costly, and they are not symmetric:

- **Too greedy** silently deletes real credentials. You will not notice; the
  repo just reports fewer hits. This is the dangerous one.
- **Too loose** adds noise you can see and grep away.

So when tightening a filter, first check what it removes from a real run:

```bash
python3 -c "
import importlib.util, json
s=importlib.util.spec_from_file_location('t','gh-trawl.py')
t=importlib.util.module_from_spec(s); s.loader.exec_module(t)
drop=[json.loads(l) for l in open('lists/results.jsonl')
      if YOUR_NEW_RULE(json.loads(l)['value'])]
print(len(drop)); [print(d['key'],'=',d['value']) for d in drop[:20]]"
```

If anything in that sample looks like a credential, the rule is too broad.

## Gotchas

- **The module filename has a hyphen**, so `import gh_trawl` does not work. Use
  `importlib.util.spec_from_file_location` (see the test file).
- **`pkill -f 'pattern'` matches your own shell** if the pattern appears in its
  command line. The same applies to `pgrep` in a watch loop — it matches itself
  and never reports completion.
- **`cmd | head` always exits 0**, so `if grep ... | head; then` is always true.
  Bit me while checking the archive for a leaked token.
- **Throttling looks like clean code.** `fetch_raw` returns `""` on any non-OK
  response, so a throttled repo logs `N files, 0 hits` and reads as having
  nothing. A run of zero-hit rows after a productive stretch means lower `-t`.
- **Truncated trees**: repos over ~100k files return a partial tree. Use it —
  `walk()` re-fetches one directory per request and took 5m20s on
  `torvalds/linux` before timing out with nothing written. It is behind
  `--deep-walk` for that reason, and the partial run is flagged `truncated=1`.
- **Search API caps at 1000 results.** `--offset` past that re-queries with a
  shrinking `stars:` window. There is a test for it with a faked `gh()`.

## Highest-value improvement

`SEED_REPOS` out-yields star-ranked repos **4.2x per repo** (9.3 findings/repo vs
2.2, measured over 3,021 repos). Top-starred repos are mostly libraries with no
deployable config. Adding self-hostable applications to that list beats any
increase to `--top`.

## Scope

Reading public repos only. Finding `grafana12345` in Grafana's repo tells you
what to *try* against a target; confirming it still works there is a separate,
authorised activity. Keep that line in the README.

Do not add anything that authenticates to, scans, or exploits a third-party
system. The output is a wordlist; what happens to it is the operator's call.
