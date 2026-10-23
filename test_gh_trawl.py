#!/usr/bin/env python3
"""
Regression tests for gh-trawl. No network, no token needed:

    python3 test_gh_trawl.py

Every case here is a bug that actually shipped at some point. If you are
tightening a filter and a test fails, read its comment before changing the
assertion -- most of these are a filter that was once too greedy and silently
deleted real findings.
"""
import importlib.util, base64, json, os, tempfile, unittest

spec = importlib.util.spec_from_file_location(
    "ght", os.path.join(os.path.dirname(os.path.abspath(__file__)), "gh-trawl.py"))
ght = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ght)


def kinds(text):
    """(key, value, kind) triples extract() finds in a blob of config."""
    return [(k, v, kind) for _, k, v, kind in ght.extract(text)]


def kind_of(key):
    nk = ght.norm_key(key)
    if ght.NOISE_KEY.search(nk) or ght.I18N_KEY.match(nk):
        return None
    return ("secret" if ght.SECRET_RE.search(nk)
            else "user" if ght.USER_RE.search(nk) else None)


class KeyMatching(unittest.TestCase):
    def test_camelcase_keys_match(self):
        # USER_RE anchors words to ^ or [_.-], so DBUser never matched and every
        # Java/.NET/Zabbix-style config was fetched then ignored.
        self.assertEqual(kind_of("DBUser"), "user")
        self.assertEqual(kind_of("DBPassword"), "secret")
        self.assertEqual(kind_of("adminUser"), "user")
        self.assertEqual(kind_of("dbUsername"), "user")
        self.assertEqual(kind_of("APIKey"), "secret")

    def test_env_var_keys_still_match(self):
        for k in ("POSTGRES_USER", "MINIO_ROOT_USER", "ADMIN_USERNAME"):
            self.assertEqual(kind_of(k), "user", k)
        for k in ("MYSQL_ROOT_PASSWORD", "JWT_SECRET", "GITHUB_TOKEN"):
            self.assertEqual(kind_of(k), "secret", k)

    def test_noise_keys_rejected(self):
        # _ROOT_URL once matched as a username because "root" was a bare word.
        for k in ("GF_SERVER_ROOT_URL", "DATABASE_URL", "REDIS_HOST",
                  "MINIO_SECRET_KEY_FILE", "UserParameter", "max_tokens"):
            self.assertIsNone(kind_of(k), k)

    def test_singular_token_is_a_credential(self):
        # Plural "tokens" counts things; singular names a credential.
        self.assertEqual(kind_of("DOCKER_INFLUXDB_INIT_ADMIN_TOKEN"), "secret")
        self.assertIsNone(kind_of("KNOWLEDGE_GRAPH_MIN_BATCH_TOKENS"))

    def test_i18n_message_keys_rejected(self):
        self.assertIsNone(kind_of("my_account.reset_password.page"))
        self.assertIsNone(kind_of("global_nav.account.tooltip"))
        # Two segments is a real setting, not a message path.
        self.assertEqual(kind_of("system.secret-key"), "secret")


class Classification(unittest.TestCase):
    def test_interpolated_is_the_only_discard(self):
        for v in ("${JWT_SECRET}", "$SECRET", "{{ .Values.pw }}", "%(secret)s",
                  "", "null", "true", "~", "[]", "2", "80"):
            self.assertEqual(ght.classify(v, "secret"), "interpolated", repr(v))

    def test_placeholders_are_findings_not_noise(self):
        # These ship to production intact -- the whole point of the tool.
        for v in ("changeme", "CHANGE-ME-OR-FAIL-TO-START", "your_api_key_here",
                  "<your-api-key>", "REPLACE_ME", "a_jwt_secret",
                  "change-this-in-production-to-32-or-higher-int",
                  "must_be_at_least_32_characters"):
            self.assertEqual(ght.classify(v, "secret"), "placeholder_default", repr(v))

    def test_real_defaults_survive(self):
        for v, want in (("admin", "weak_default"), ("minioadmin", "weak_default"),
                        ("rootpass", "medium_default"), ("Password123", "medium_default"),
                        ("P@$$w0rd", "medium_default"),
                        ("8f4c1b9e2a7d6350af91c2e4b8d70516", "high_entropy_default")):
            self.assertEqual(ght.classify(v, want and "secret"), want, repr(v))

    def test_prose_is_not_high_entropy(self):
        # Shannon entropy rates snake_case English as random because it counts
        # distinct characters, so descriptions outranked real secrets.
        self.assertEqual(ght.classify("client_secret_from_auth0_dashboard", "secret"),
                         "placeholder_default")


class ValueParsing(unittest.TestCase):
    def test_leaked_key_prefix_stripped(self):
        # KV_RE runs to end of line: "api_key: str | None = None" over-captured.
        self.assertEqual(kinds("api_key: str | None = None"), [("api_key", "None", "secret")])
        self.assertEqual(kinds("password = {value}"), [("password", "{value}", "secret")])

    def test_base64_padding_is_not_a_leaked_key(self):
        # BARE_KEY was once ^[A-Za-z_][\w.-]*=$ which ate base64 with one "=".
        for v in ("U2VjdXJlTmFjb3NBdXRoVG9rZW5Gb3JEZW1vUHVycG9zZXMxMjM=",
                  "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=", "dGVzdA=="):
            self.assertFalse(ght.BARE_KEY.match(v), v)
        for v in ("AI21_MODEL_LIST=", "GOOGLE_PROXY_URL="):
            self.assertTrue(ght.BARE_KEY.match(v), v)

    def test_base64_value_is_preserved_intact(self):
        got = kinds("secret=dGVzdGluZzEyMzQ1Njc4OTA=")
        self.assertIn(("secret", "dGVzdGluZzEyMzQ1Njc4OTA=", "secret"), got)

    def test_source_code_is_not_a_credential(self):
        self.assertEqual(kinds("apiKey=flags.apiKey ?? process.env.N8N_API_KEY"), [])
        self.assertEqual(kinds("clientSecret=z.string().min(1)"), [])
        self.assertEqual(kinds('UserParameter=mysql.ping[*], mysqladmin -h"1"'), [])

    def test_braces_survive_the_code_filter(self):
        # CODEY once held {} for TS object literals and killed {value} with it.
        self.assertEqual(ght.classify("{value}", "secret"), "weak_default")

    def test_dockerfile_env_and_url_creds(self):
        self.assertEqual(kinds("ENV RABBITMQ_DEFAULT_PASS guest"),
                         [("RABBITMQ_DEFAULT_PASS", "guest", "secret")])
        got = kinds("DATABASE_URL=postgres://admin:changeme@db:5432/app")
        self.assertIn(("URL[user]", "admin", "user"), got)
        self.assertIn(("URL[pass]", "changeme", "secret"), got)

    def test_comments_ignored(self):
        self.assertEqual(kinds("# DBPassword=hunter2"), [])
        self.assertEqual(kinds(";  password = hunter2"), [])


class Base64Decoding(unittest.TestCase):
    def test_plain_secret_decoded(self):
        enc = base64.b64encode(b"SecureNacosAuthTokenForDemo123").decode()
        got = dict((k, v) for k, v, _ in kinds(f"NACOS_AUTH_TOKEN={enc}"))
        self.assertEqual(got["NACOS_AUTH_TOKEN[b64]"], "SecureNacosAuthTokenForDemo123")

    def test_json_blob_walked(self):
        enc = base64.b64encode(
            json.dumps({"UserID": "defaultUser", "Password": "defaultPassword"}).encode()).decode()
        got = dict((k, v) for k, v, _ in kinds(f"AUTH_CREDENTIALS={enc}"))
        self.assertEqual(got["AUTH_CREDENTIALS[b64].UserID"], "defaultUser")
        self.assertEqual(got["AUTH_CREDENTIALS[b64].Password"], "defaultPassword")

    def test_embedded_config_re_extracted(self):
        enc = base64.b64encode(b"DB_USER=root\nDB_PASSWORD=s3cr3t\nPORT=5432").decode()
        got = dict((k, v) for k, v, _ in kinds(f"APP_SECRET={enc}"))
        self.assertEqual(got["APP_SECRET[b64].DB_USER"], "root")
        self.assertEqual(got["APP_SECRET[b64].DB_PASSWORD"], "s3cr3t")

    def test_lookalikes_not_decoded(self):
        # Hex digests and AWS key ids are valid base64 alphabet but decode to junk.
        for v in ("8f4c1b9e2a7d6350af91c2e4b8d70516", "AKIAIOSFODNN7EXAMPLE",
                  "minioadmin", "abcdefghijklmnop"):
            self.assertIsNone(ght.b64_decode(v), v)


class WordlistFiltering(unittest.TestCase):
    def ok(self, v, min_len=4):
        return ght.usable(v, min_len)[0]

    def reason(self, v, min_len=4):
        return ght.usable(v, min_len)[1]

    def test_rejects(self):
        self.assertEqual(self.reason("密码"), "non-ascii")
        self.assertEqual(self.reason("API Key"), "whitespace")
        self.assertEqual(self.reason("str | None = None"), "whitespace")
        self.assertEqual(self.reason("{"), "no-alnum")
        self.assertEqual(self.reason("~/project"), "path")
        self.assertEqual(self.reason("/var/lib/pg"), "path")
        self.assertEqual(self.reason("</mail_crypt/key.pem"), "path")
        self.assertEqual(self.reason("https://example.com"), "url")
        self.assertEqual(self.reason('{"data":{"token":"x"}}'), "json-fragment")
        self.assertEqual(self.reason("{env}WEBDAV_PASSWORD"), "template-fragment")

    def test_keeps(self):
        for v in ("minioadmin", "changeme", "<secret>", "your_db_password",
                  "MDAwMDAwMDAw+/aaa=", "EK-5jnKfjrGRm<77"):
            self.assertTrue(self.ok(v), v)

    def test_min_length_default_keeps_top_defaults(self):
        # admin/root/guest/123456 are the most widely shipped values in the data.
        for v in ("admin", "root", "guest", "pass", "123456", "secret"):
            self.assertTrue(self.ok(v), v)
        for v in ("admin", "root", "guest", "123456"):
            self.assertFalse(self.ok(v, 8), v)

    def test_wrapped_values_yield_both_forms(self):
        self.assertEqual(ght.variants("<secret>"), ["<secret>", "secret"])
        self.assertEqual(ght.variants("{value}"), ["{value}", "value"])
        self.assertEqual(ght.variants("minioadmin"), ["minioadmin"])


class SearchPaging(unittest.TestCase):
    def test_offset_crosses_the_1000_result_cap(self):
        universe = [{"full_name": f"o/r{i:04d}", "stargazers_count": 10000 - i}
                    for i in range(2500)]

        class R:
            def __init__(s, d): s.d = d
            def json(s): return s.d

        def fake_gh(url, **p):
            q = p["q"]
            if ".." in q:
                lo, hi = (int(x) for x in q.split(":")[1].split(".."))
                pool = [r for r in universe if lo <= r["stargazers_count"] <= hi]
            else:
                lo = int(q.split(">")[1])
                pool = [r for r in universe if r["stargazers_count"] > lo]
            pool = pool[:1000]                      # GitHub's hard cap
            return R({"items": pool[(p["page"] - 1) * 100: p["page"] * 100]})

        real_gh, real_sleep = ght.gh, ght.time.sleep
        ght.gh, ght.time.sleep = fake_gh, lambda *_: None
        try:
            got = ght.top_repos(5, 7000, offset=1000)
            self.assertEqual([r["full_name"] for r in got],
                             [f"o/r{i:04d}" for i in range(1000, 1005)])
            self.assertEqual(len(ght.top_repos(50, 7000, offset=2490)), 10)
        finally:
            ght.gh, ght.time.sleep = real_gh, real_sleep


class WordlistOutput(unittest.TestCase):
    def test_end_to_end(self):
        recs = [
            ("a/a", ".env", "ADMIN_USER", "admin", "user"),
            ("a/a", ".env", "ADMIN_PASSWORD", "changeme", "secret"),
            ("b/b", ".env", "DB_USER", "admin", "user"),
            ("b/b", ".env", "DB_PASSWORD", "s3cr3tpw", "secret"),
            ("c/c", ".env", "API_KEY", "密码", "secret"),
        ]
        with tempfile.TemporaryDirectory() as d:
            jl = os.path.join(d, "r.jsonl")
            with open(jl, "w") as fh:
                for repo, path, k, v, kind in recs:
                    fh.write(json.dumps({"repo": repo, "path": path, "key": k, "value": v,
                                         "kind": kind, "line": 1, "stars": 1,
                                         "entropy": 0.0, "class": "weak_default"}) + "\n")
            u, p, c, ph, ex = ght.wordlists(jl, os.path.join(d, "w"))
            with open(os.path.join(d, "w", "users.txt")) as fh:
                users = fh.read().split()
            with open(os.path.join(d, "w", "combos.txt")) as fh:
                combos = fh.read().split()
            with open(os.path.join(d, "w", "excluded.tsv")) as fh:
                excluded = fh.read()

        self.assertEqual(users[0], "admin")          # seen in 2 repos -> ranked first
        self.assertIn("admin:changeme", combos)
        self.assertIn("admin:s3cr3tpw", combos)
        self.assertIn("non-ascii", excluded)         # nothing is dropped silently
        self.assertEqual(ex, 1)

    def test_combos_skip_colon_bearing_values(self):
        # hydra -C splits on the first colon, so these pairs would be corrupt.
        recs = [("a/a", ".env", "USER", "@bot:matrix.org", "user"),
                ("a/a", ".env", "PASSWORD", "hunter22", "secret")]
        with tempfile.TemporaryDirectory() as d:
            jl = os.path.join(d, "r.jsonl")
            with open(jl, "w") as fh:
                for repo, path, k, v, kind in recs:
                    fh.write(json.dumps({"repo": repo, "path": path, "key": k, "value": v,
                                         "kind": kind, "line": 1, "stars": 1,
                                         "entropy": 0.0, "class": "weak_default"}) + "\n")
            ght.wordlists(jl, os.path.join(d, "w"))
            with open(os.path.join(d, "w", "combos.txt")) as fh:
                combos = fh.read().split()
        self.assertEqual(combos, [])


class Paths(unittest.TestCase):
    def scanned(self, p):
        return bool(ght.CANDIDATE_PATH.search(p)) and not ght.SKIP_PATH.search(p)

    def test_scanned(self):
        for p in ("docker-compose.yml", ".env.example", "Dockerfile",
                  "src/appsettings.Production.json", "charts/app/values.yaml",
                  "terraform.tfvars", "wp-config.php",
                  "quarkus/server/src/main/resources/application.properties"):
            self.assertTrue(self.scanned(p), p)

    def test_skipped(self):
        # .ts config is source code; l10n bundles flooded one run with 215 hits.
        for p in ("packages/x/config.ts", "src/__tests__/configure.test.ts",
                  "tests/config.yml", "node_modules/x/.env", "README.md",
                  "org/sonar/l10n/core.properties",
                  "themes/base/login/messages/messages_en.properties"):
            self.assertFalse(self.scanned(p), p)


class KeyFile(unittest.TestCase):
    def test_dump_and_reload_does_not_duplicate(self):
        before = (len(ght.SECRET_KEYS), len(ght.USER_KEYS))
        with tempfile.TemporaryDirectory() as d:
            kf = os.path.join(d, "keys.txt")
            ght.dump_keys(kf)
            self.assertEqual(ght.load_keys(kf, replace=False), before)
            with open(kf, "a") as fh:
                fh.write("\nvault[_-]?id\nuser: operator\n")
            self.assertEqual(ght.load_keys(kf, replace=False),
                             (before[0] + 1, before[1] + 1))
        # restore the module-level regexes for any later test
        ght.SECRET_RE = ght.re.compile("|".join(ght.SECRET_KEYS), ght.re.I)
        ght.USER_RE = ght.re.compile("|".join(ght.USER_KEYS), ght.re.I)


if __name__ == "__main__":
    unittest.main(verbosity=2)
