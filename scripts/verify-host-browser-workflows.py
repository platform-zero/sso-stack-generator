#!/usr/bin/env python3
"""Selected synthetic host browser proof; NOT an installer or an admission authority.

Requires Python Playwright + Chromium at runtime. No browser/network use on import.
See docs/browser-acceptance.md for the exact protected input and evidence contract.
"""
import argparse
from datetime import date
from decimal import Decimal
import hashlib
import json
import os
import re
import signal
import stat
import time
from urllib.parse import urlsplit

LIMIT = 262144
HEX = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
SCOPES = ("transport", "readiness", "sso", "role_denial", "workflow",
          "persistence", "cleanup", "logout")
# Public source pins for the retained images, NOT installed-version assertions:
# firefly-iii/firefly-iii ba26768619842a4926655f315716f1b7788933d7 (v6.7.9):
# resources/assets/v3/js/boot/axios.js, api/model/{account,transaction}/*,
# app/Api/V1/Requests/Models/{Account,Transaction}/{Store,Update}Request.php.
# hcengineering/platform b9f2f9d5b110e18e0484c90e4358f0fc8ae419bd (v0.7.423):
# tests/sanity/tests/model/{select-workspace-page,tracker/*}.ts,
# plugins/{login-resources,setting-resources}/src/components/{CreateWorkspaceForm,General}.svelte,
# foundations/core/packages/account-client/src/client.ts, server/account-service/src/index.ts.
# Huly exact-delete blocker at this pin: server/account/src/operations.ts:1697-1717
# only schedules pending-deletion; :1839-1849 filters deleting/disabled rows;
# :1855-1878 permits getWorkspacesInfo only to the system account. Consequently
# native account-list disappearance CANNOT prove cleanup. A module-owned exact
# fixture/status hook is required; delete-created refuses BEFORE any mutation.
WORKFLOWS = {"firefly-iii": "firefly-iii-6.7.9-cookie-v1", "huly": "huly-0.7.423-ui-v1"}
CLEANUP = ("delete-created", "retain-created-for-restart-probe")
UUID = re.compile(r"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\Z")
PREREQUISITES = {"native-subject-required", "firefly-native-cookie-csrf-unproven",
                 "firefly-native-cookie-api-unproven", "huly-native-cookie-session-unproven",
                 "huly-native-account-mismatch", "huly-native-workspace-permission-unproven",
                 "huly-native-exact-cleanup-hook-required", "huly-websocket-policy-unavailable"}


class Refused(Exception):
    """Only fixed, non-sensitive reason codes may leave the harness."""


def need(condition, code="invalid-input"):
    if not condition:
        raise Refused(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, "duplicate-key")
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=pairs,
                       parse_constant=lambda _: need(False))
    need(isinstance(value, dict))
    return value


class ProtectedReader:
    """Walk from a trusted anchor with openat, never following a link.

    Production ALWAYS uses / and uid 0. Alternate anchors are dependency injection
    for the isolated unit tests, not a command line or deployment option.
    """
    def __init__(self, anchor="/", owner=0):
        self.anchor, self.owner = anchor, owner

    def directory(self, info):
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == self.owner
             and not info.st_mode & 0o022, "unsafe-parent")

    def read(self, path, private=False, owner=None):
        need(isinstance(path, str) and path.startswith("/") and "\x00" not in path)
        parts = path.split("/")[1:]
        need(parts and all(p not in ("", ".", "..") for p in parts), "unsafe-path")
        directory = os.open(self.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.directory(os.fstat(directory))
            for part in parts[:-1]:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=directory)
                os.close(directory)
                directory = nxt
                self.directory(os.fstat(directory))
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory)
            try:
                before = os.fstat(fd)
                expected_owner = self.owner if owner is None else owner
                need(stat.S_ISREG(before.st_mode) and before.st_uid == expected_owner
                     and before.st_nlink == 1 and before.st_size <= LIMIT
                     and not before.st_mode & (0o077 if private else 0o022), "unsafe-file")
                chunks, size = [], 0
                while True:
                    chunk = os.read(fd, min(16384, LIMIT + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    need(size <= LIMIT, "oversize-input")
                after = os.fstat(fd)
                need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                      before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                                             after.st_mtime_ns, after.st_ctime_ns), "input-raced")
                return b"".join(chunks)
            finally:
                os.close(fd)
        finally:
            os.close(directory)


def https_url(value):
    need(isinstance(value, str) and len(value) <= 2048 and not re.search(r"[\s\\%]", value),
         "invalid-url")
    parsed = urlsplit(value)
    need(parsed.scheme == "https" and parsed.hostname and parsed.username is None
         and parsed.password is None and parsed.port in (None, 443) and not parsed.fragment
         and not parsed.query and re.fullmatch(r"[a-z0-9.-]+", parsed.hostname)
         and "." in parsed.hostname and not re.fullmatch(r"[0-9.]+", parsed.hostname)
         and all(p not in (".", "..") for p in parsed.path.split("/")), "normal-https-required")
    return parsed


def origin(value):
    parsed = urlsplit(value)
    return parsed.scheme + "://" + parsed.netloc


def selector(value):
    need(isinstance(value, str) and 0 < len(value) <= 512 and "\x00" not in value)


def validate_plan(plan, now):
    need(plan.get("schemaVersion") == 1 and type(plan["schemaVersion"]) is int
         and plan.get("scope") == "host-synthetic-browser"
         and plan.get("exclusiveFixture") is True, "wrong-scope")
    need(re.fullmatch(r"[0-9a-f]{32}", plan.get("runId", "")) is not None)
    need(ID.fullmatch(plan.get("fixtureId", "")) is not None)
    need(type(plan.get("issuedAt")) is int and type(plan.get("expiresAt")) is int
         and plan["issuedAt"] <= now <= plan["expiresAt"]
         and 0 < plan["expiresAt"] - plan["issuedAt"] <= 1800, "expired-selection")
    release, state_root = plan.get("release"), plan.get("stateRoot")
    for path in (release, state_root):
        need(isinstance(path, str) and path.startswith("/")
             and all(p not in ("", ".", "..") for p in path.split("/")[1:]))
    need(re.fullmatch(re.escape(state_root) + r"/releases/[A-Za-z0-9._-]+", release)
         is not None, "release-scope")
    for key in ("marker", "journal", "receipt"):
        binding = plan.get(key, {})
        need(set(binding) == {"path", "sha256"} and HEX.fullmatch(binding["sha256"]) is not None)
    need(plan["receipt"]["path"] == release + "/installation-receipt.json"
         and plan["journal"]["path"] == state_root + "/.install-intent.json", "receipt-scope")
    kc, portal, apps = plan.get("keycloak", {}), plan.get("portal", {}), plan.get("apps")
    https_url(kc["url"])
    need(kc["url"] == origin(kc["url"]) and ID.fullmatch(kc["realm"]) is not None)
    https_url(kc["logout_url"])
    need(origin(kc["logout_url"]) == kc["url"] and
         urlsplit(kc["logout_url"]).path.startswith("/realms/" + kc["realm"] + "/"))
    selector(kc["logout_selector"])
    https_url(portal["url"])
    selector(portal["authenticated_selector"])
    selector(portal["identity_selector"])
    need(isinstance(apps, list) and 1 <= len(apps) <= 32)
    ids, origins = set(), {origin(portal["url"]), kc["url"]}
    need(len(origins) == 2, "distinct-origins-required")
    for app in apps:
        name = app["id"]
        need(ID.fullmatch(name) is not None and name not in ids and name not in ("portal", "keycloak"))
        ids.add(name)
        https_url(app["url"])
        need(origin(app["url"]) not in origins, "distinct-origins-required")
        origins.add(origin(app["url"]))
        selector(app["authenticated_selector"])
        selector(app["identity_selector"])
        if "sso_selector" in app:
            selector(app["sso_selector"])
        if "denial" in app:
            denial = app["denial"]
            https_url(denial["url"])
            need(origin(denial["url"]) == origin(app["url"]))
            selector(denial["selector"])
        need(app.get("driver") in ("firefly", "firefly-iii", "huly", "jupyterhub", "unimplemented"),
             "unsupported-driver")
        if app["driver"] in WORKFLOWS:
            workflow = app.get("workflow", {})
            keys = {"kind", "cleanup"} | ({"currency", "date"} if app["driver"] == "firefly-iii" else {"language"})
            need(isinstance(workflow, dict) and set(workflow) == keys
                 and workflow["kind"] == WORKFLOWS[app["driver"]]
                 and workflow["cleanup"] in CLEANUP, "invalid-app-workflow-plan")
            need(app["url"] == origin(app["url"]) + "/", "native-app-root-required")
            if app["driver"] == "firefly-iii":
                need(isinstance(workflow["currency"], str)
                     and re.fullmatch(r"[A-Z]{3}", workflow["currency"]), "invalid-fixture-currency")
                need(isinstance(workflow["date"], str)
                     and date.fromisoformat(workflow["date"]).isoformat() == workflow["date"], "invalid-fixture-date")
            else:
                need(workflow["language"] == "en", "huly-english-ui-required")
        if app["driver"] == "jupyterhub":
            https_url(app["server_url"])
            need(origin(app["server_url"]) == origin(app["url"])
                 and re.fullmatch(r"/user/[A-Za-z0-9_-]+/", urlsplit(app["server_url"]).path),
                 "server-scope")
    need(plan.get("selectedApps") == [a["id"] for a in apps], "selected-set-mismatch")
    return origins


class Binding:
    """Read-only CAS against caller-pinned authority, never consumes approval."""
    def __init__(self, reader, path, expected):
        need(HEX.fullmatch(expected) is not None)
        self.reader, self.path, self.expected = reader, path, expected
        self.cancelled = False
        raw = reader.read(path)
        need(digest(raw) == expected, "selection-cas-changed")
        self.plan = decode(raw)
        self.check()

    def check(self):
        need(not self.cancelled, "run-deadline")
        need(digest(self.reader.read(self.path)) == self.expected, "selection-cas-changed")
        plan = self.plan
        self.origins = validate_plan(plan, int(time.time()))
        values = {}
        for key in ("marker", "journal", "receipt"):
            raw = self.reader.read(plan[key]["path"])
            need(digest(raw) == plan[key]["sha256"], key + "-cas-changed")
            values[key] = decode(raw)
        need(values["marker"] == {"schemaVersion": 1, "scope": "host-synthetic-browser",
             "fixtureId": plan["fixtureId"], "selectedApps": plan["selectedApps"]}, "marker-mismatch")
        journal = values["journal"]
        need(journal == values["receipt"] and journal.get("schemaVersion") == 1
             and journal.get("phase") == "active" and journal.get("release") == plan["release"]
             and isinstance(journal.get("inputs"), dict)
             and all(isinstance(journal["inputs"].get(k), str)
                     and HEX.fullmatch(journal["inputs"][k])
                     for k in ("bundle.json", "stack.ir.json", "source-provenance.json"))
             and all(v is None or isinstance(v, str) and HEX.fullmatch(v)
                     for v in journal["inputs"].values()), "inactive-or-mismatched-receipt")
        # Input hashes are existing installer authority, not a new installer.
        # In particular do NOT open its encrypted stores or runtime inputs.


def credentials(reader, path=None, fd=None):
    if path is not None:
        raw = reader.read(path, private=True, owner=os.geteuid())
    else:
        need(type(fd) is int and fd >= 3, "protected-credentials-required")
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.geteuid())
             and info.st_nlink == 1 and not info.st_mode & 0o077 and info.st_size <= LIMIT,
             "unsafe-credential-fd")
        raw = os.pread(fd, LIMIT + 1, 0)
        after = os.fstat(fd)
        need(len(raw) <= LIMIT and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
             info.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                                  after.st_mtime_ns, after.st_ctime_ns), "credential-fd-raced")
    value = decode(raw)
    for actor in ("member", "denied"):
        record = value.get(actor, {})
        for key in ("username", "password", "identity"):
            need(isinstance(record.get(key), str) and 0 < len(record[key]) <= 1024,
                 "missing-fixture-credentials")
        identities = record.get("identities", {})
        need(isinstance(identities, dict) and all(isinstance(k, str) and ID.fullmatch(k)
             and isinstance(v, str) and 0 < len(v) <= 1024 for k, v in identities.items()),
             "invalid-fixture-identities")
    subjects = value["member"].get("nativeSubjects", {})
    need(isinstance(subjects, dict) and all(isinstance(k, str) and ID.fullmatch(k)
         and isinstance(v, str) and UUID.fullmatch(v) for k, v in subjects.items()),
         "invalid-native-subjects")
    need(value["member"]["username"] != value["denied"]["username"], "distinct-actors-required")
    return value


class Evidence:
    def __init__(self, plan, plan_sha256):
        self.plan, self.plan_sha256 = plan, plan_sha256
        self.fixtures = []  # Only created synthetic IDs and curated-value digests, never response bodies.
        self.rows = {(target, scope): {"target": target, "scope": scope,
                     "state": "unproven", "code": "not-executed"}
                     for target in ["portal"] + plan["selectedApps"] for scope in SCOPES}
        for scope in ("role_denial", "workflow", "persistence", "cleanup"):
            self.rows.pop(("portal", scope))

    def set(self, target, scope, state="passed", code="observed"):
        # A later actor/navigation must never erase an earlier failed observation.
        if self.rows.get((target, scope), {}).get("state") == "failed":
            return
        self.rows[target, scope] = dict(target=target, scope=scope, state=state, code=code)

    def result(self):
        rows = list(self.rows.values())
        passed = all(row["state"] == "passed" for row in rows)
        return {"schemaVersion": 1, "scope": "host-synthetic-browser", "runId": self.plan["runId"],
                "selectedApps": self.plan["selectedApps"], "browserScopesPassed": passed,
                "bindings": {"planSha256": self.plan_sha256,
                             **{key + "Sha256": self.plan[key]["sha256"]
                                for key in ("marker", "journal", "receipt")}},
                "completeAcceptance": False, "checks": rows, "fixtures": self.fixtures,
                "durablePersistence": {"state": "unproven", "code": "no-authorized-restart-data-probe"},
                "recovery": {"state": "unproven", "code": "no-authorized-restart-proof"},
                "visual": {"state": "unproven", "code": "no-secret-bearing-capture"}}


class Harness:
    def __init__(self, binding, secret, browser):
        self.binding, self.plan, self.secret, self.browser = binding, binding.plan, secret, browser
        self.evidence = Evidence(self.plan, binding.expected)
        self.contexts = []

    def context(self):
        # No persistent profiles, HAR, video, trace, screenshot, TLS exception,
        # client certificate, HTTP credentials, token grant, or custom resolver.
        context = self.browser.new_context(service_workers="block", accept_downloads=False)
        context.set_default_timeout(7000)
        context.set_default_navigation_timeout(10000)
        allowed = self.binding.origins
        def route(request_route):
            url = urlsplit(request_route.request.url)
            if url.scheme == "https" and origin(request_route.request.url) in allowed:
                request_route.continue_()
            else:
                request_route.abort("blockedbyclient")
        context.route("**/*", route)
        self.contexts.append(context)
        huly_origins = {origin(app["url"]) for app in self.plan["apps"] if app["driver"] == "huly"}
        if huly_origins:
            websocket_available = callable(getattr(context, "route_web_socket", None))
            if not websocket_available:
                for app in self.plan["apps"]:
                    if app["driver"] == "huly":
                        self.evidence.set(app["id"], "workflow", "unproven", "huly-websocket-policy-unavailable")
            need(websocket_available, "huly-websocket-policy-unavailable")
            def websocket(socket):
                try:
                    self.binding.check()
                except Exception:
                    socket.close()
                    return
                parsed = urlsplit(socket.url)
                secure_origin = "https://" + parsed.netloc
                if (parsed.scheme == "wss" and secure_origin in huly_origins
                        and any(parsed.path == path or parsed.path.startswith(path + "/")
                                for path in ("/_transactor", "/_collaborator"))):
                    socket.connect_to_server()
                else:
                    socket.close()
            context.route_web_socket("**/*", websocket)
        return context

    def visit(self, page, target, url):
        self.binding.check()
        try:
            response = page.goto(url, wait_until="domcontentloaded")
            need(response is not None, "no-http-response")
        except Exception:
            self.evidence.set(target, "transport", "failed", "navigation-or-tls-failed")
            raise
        self.evidence.set(target, "transport")
        if response.status >= 500:
            self.evidence.set(target, "readiness", "failed", "http-server-unready")
            raise Refused("http-server-unready")
        return response

    def authenticated(self, page, config, actor):
        page.locator(config["authenticated_selector"]).wait_for(state="visible")
        need(origin(page.url) == origin(config["url"]), "wrong-app-origin")
        need(page.locator('input[type="password"]:visible').count() == 0, "native-login-visible")
        # Text comparison only, never expose account names in evidence.
        text = page.locator(config["identity_selector"]).inner_text().strip()
        expected = actor.get("identities", {}).get(config.get("id", "portal"), actor["identity"])
        need(text == expected, "wrong-browser-identity")

    def keycloak_login(self, page, actor):
        kc = self.plan["keycloak"]
        page.wait_for_url(lambda url: origin(str(url)) == kc["url"] and
                          urlsplit(str(url)).path.startswith("/realms/" + kc["realm"] + "/"))
        need(origin(page.url) == kc["url"], "credentials-origin-refused")
        page.locator("#username").wait_for(state="visible")
        self.binding.check()
        page.locator("#username").fill(actor["username"])
        page.locator("#password").fill(actor["password"])
        page.locator("#kc-login").click()

    def portal_login(self, context, actor):
        page = context.new_page()
        self.visit(page, "portal", self.plan["portal"]["url"])
        self.keycloak_login(page, actor)
        self.authenticated(page, self.plan["portal"], actor)
        self.evidence.set("portal", "readiness")
        self.evidence.set("portal", "sso", code="keycloak-browser-login")
        return page

    def api(self, context, method, url, **kwargs):
        need(origin(url) in self.binding.origins, "api-origin-refused")
        self.binding.check()  # Includes reads and cleanup, not just creation.
        response = context.request.fetch(url, method=method, max_redirects=0,
                                         timeout=7000, **kwargs)
        return response

    @staticmethod
    def body(response, statuses=(200,)):
        need(response.status in statuses, "app-api-status")
        return response.json()

    def native_subject(self, app):
        subject = self.secret["member"].get("nativeSubjects", {}).get(app["id"])
        need(isinstance(subject, str) and UUID.fullmatch(subject), "native-subject-required")
        return subject

    def ui(self, page, app, css):
        self.binding.check()
        need(origin(page.url) == origin(app["url"]), "wrong-app-origin")
        need(page.locator('input[type="password"]:visible').count() == 0, "native-login-visible")
        locator = page.locator(css)
        locator.wait_for(state="visible")
        need(locator.count() == 1, "ambiguous-native-control")
        return locator

    @staticmethod
    def object_id(value):
        need(isinstance(value, (str, int)) and not isinstance(value, bool)
             and re.fullmatch(r"[1-9][0-9]*", str(value)), "invalid-created-id")
        return str(value)

    def fixture_metadata(self, app, objects):
        row = {"target": app["id"], "kind": app["workflow"]["kind"],
               "runId": self.plan["runId"], "lifecycle": "cleanup-unproven",
               "digestScope": "curated-native-values-not-whole-object", "objects": objects}
        self.evidence.fixtures.append(row)
        return row

    @staticmethod
    def value_sha(value):
        return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())

    def firefly_iii(self, context, page, app):
        """Native Passport browser cookie + native CSRF, NEVER a PAT/second login.

        API is the pinned app's own UI API. Both accounts and exactly one
        withdrawal are created/read/changed. Rules/webhooks are disabled for the
        synthetic transaction. Cleanup never cascades through an unknown child.
        """
        target, workflow = app["id"], app["workflow"]
        base = origin(app["url"]) + "/api/v1"
        objects, accounts, transaction = [], [], None
        metadata = self.fixture_metadata(app, objects)
        phase, clean = "workflow", True
        def api(method, path, **kw):
            self.binding.check()
            need(origin(page.url) == origin(app["url"]), "wrong-app-origin")
            need(page.locator('input[type="password"]:visible').count() == 0, "native-login-visible")
            cookies = context.cookies([base])
            for name in ("__Host-firefly_app", "laravel_token"):
                matches = [c for c in cookies if c["name"] == name]
                need(len(matches) == 1 and matches[0].get("secure") and matches[0].get("httpOnly"),
                     "firefly-native-cookie-csrf-unproven")
            csrf = page.locator('meta[name="csrf-token"]')
            need(csrf.count() == 1, "firefly-native-cookie-csrf-unproven")
            token = csrf.get_attribute("content")
            need(isinstance(token, str) and 0 < len(token) <= 512, "firefly-native-cookie-csrf-unproven")
            headers = {"Accept": "application/json", "X-CSRF-TOKEN": token,
                       "X-Requested-With": "XMLHttpRequest", "Origin": origin(app["url"]),
                       "Referer": app["url"]}
            return self.api(context, method, base + path, headers=headers, **kw)
        def account_pin(data, expected):
            attrs = data["attributes"]
            need(self.object_id(data["id"]) == expected["id"]
                 and all(attrs.get(k) == expected[k] for k in ("name", "type", "notes")), "fixture-object-changed")
            if expected["type"] == "asset":
                need(attrs.get("currency_code") == workflow["currency"]
                     and attrs.get("account_role") == "defaultAsset", "fixture-object-changed")
            return {k: expected[k] for k in ("id", "name", "type", "notes")}
        def owned_account(row):
            result = self.body(api("GET", "/accounts/" + row["id"]))["data"]
            return account_pin(result, row)
        def owned_transaction():
            result = self.body(api("GET", "/transactions/" + transaction["id"]))["data"]
            attrs = result["attributes"]
            need(self.object_id(result["id"]) == transaction["id"]
                 and len(attrs["transactions"]) == 1, "fixture-object-changed")
            split = attrs["transactions"][0]
            need(split["type"] == "withdrawal" and split["description"] == transaction["description"]
                 and split.get("notes") == transaction["notes"]
                 and self.object_id(split["source_id"]) == accounts[0]["id"]
                 and self.object_id(split["destination_id"]) == accounts[1]["id"]
                 and split["currency_code"] == workflow["currency"]
                 and Decimal(split["amount"]) == Decimal("1.25")
                 and split["date"].split("T")[0] == workflow["date"], "fixture-object-changed")
            return {"id": transaction["id"], "journal": self.object_id(split["transaction_journal_id"]),
                    "description": split["description"], "notes": split["notes"],
                    "source": accounts[0]["id"], "destination": accounts[1]["id"],
                    "amount": "1.25", "date": workflow["date"], "currency": workflow["currency"]}
        try:
            subject = self.native_subject(app)
            response = api("GET", "/about/user")
            need(response.status == 200, "firefly-native-cookie-api-unproven")
            need(response.json()["data"]["attributes"]["email"] == subject, "api-actor-mismatch")
            marker = "p0-browser-" + self.plan["runId"]
            for kind in ("asset", "expense"):
                row = {"name": marker + "-" + kind, "type": kind, "notes": marker}
                payload = dict(row, currency_code=workflow["currency"])
                if kind == "asset":
                    payload.update(account_role="defaultAsset", opening_balance="0")
                data = self.body(api("POST", "/accounts", data=payload), (200, 201))["data"]
                row["id"] = self.object_id(data["id"])
                need(all(row["id"] != other["id"] for other in accounts), "duplicate-created-id")
                accounts.append(row)
                record = {"kind": kind + "-account", "id": row["id"],
                          "sha256": self.value_sha({k: row[k] for k in ("id", "name", "type", "notes")}),
                          "observation": "created-id-only"}
                objects.append(record)  # Retain known IDs even if the first pin fails.
                account_pin(data, row)
                owned_account(row)
                record["observation"] = "read-verified"
            split = {"type": "withdrawal", "date": workflow["date"], "amount": "1.25",
                     "currency_code": workflow["currency"], "description": marker + "-withdrawal",
                     "notes": marker, "source_id": accounts[0]["id"], "destination_id": accounts[1]["id"]}
            data = self.body(api("POST", "/transactions", data={"apply_rules": False, "fire_webhooks": False,
                             "transactions": [split]}), (200, 201))["data"]
            transaction = {"id": self.object_id(data["id"]), "description": split["description"], "notes": marker}
            objects.append({"kind": "withdrawal", "id": transaction["id"],
                            "sha256": self.value_sha(split), "observation": "created-id-only"})
            objects[-1]["sha256"] = self.value_sha(owned_transaction())
            objects[-1]["observation"] = "read-verified"
            for row, record in zip(accounts, objects):
                owned_account(row)
                changed = dict(row, name=row["name"] + "-changed")
                record["observation"] = "change-unconfirmed"
                data = self.body(api("PUT", "/accounts/" + row["id"], data={"name": changed["name"]}))["data"]
                account_pin(data, changed)
                row.update(changed)
                record["sha256"] = self.value_sha(owned_account(row))
                record["observation"] = "read-verified"
            pin = owned_transaction()
            description = transaction["description"] + "-changed"
            objects[-1]["observation"] = "change-unconfirmed"
            self.body(api("PUT", "/transactions/" + transaction["id"], data={"apply_rules": False,
                "fire_webhooks": False, "transactions": [{"transaction_journal_id": pin["journal"],
                                                          "description": description}]}))
            transaction["description"] = description
            objects[-1]["sha256"] = self.value_sha(owned_transaction())
            objects[-1]["observation"] = "read-verified"
            self.evidence.set(target, "workflow", code="browser-cookie-accounts-transaction-create-read-change")
            phase = "persistence"
            page.reload(wait_until="domcontentloaded")
            self.authenticated(page, app, self.secret["member"])
            for row in accounts:
                owned_account(row)
            owned_transaction()
            self.evidence.set(target, "persistence", code="read-after-browser-reload-only")
        except Refused as exc:
            self.evidence.set(target, phase, "unproven" if str(exc) in PREREQUISITES else "failed",
                              str(exc) if str(exc) in PREREQUISITES else "synthetic-object-roundtrip-failed")
        except Exception:
            self.evidence.set(target, phase, "failed", "synthetic-object-roundtrip-failed")
        finally:
            if workflow["cleanup"] == "retain-created-for-restart-probe":
                metadata["lifecycle"] = "retained-by-explicit-plan"
                self.evidence.set(target, "cleanup", "unproven", "retained-for-authorized-restart-probe")
            else:
                try:
                    if transaction is not None:
                        owned_transaction()
                        need(api("DELETE", "/transactions/" + transaction["id"]).status == 204, "fixture-cleanup-failed")
                        need(api("GET", "/transactions/" + transaction["id"]).status == 404, "fixture-cleanup-unconfirmed")
                        objects[-1]["observation"] = "deleted-after-exact-read"
                    for row in reversed(accounts):
                        owned_account(row)
                        children = self.body(api("GET", "/accounts/" + row["id"] + "/transactions"))
                        need(children["data"] == [] and children["meta"]["pagination"]["total"] == 0,
                             "unexpected-fixture-children")
                        need(api("DELETE", "/accounts/" + row["id"]).status == 204, "fixture-cleanup-failed")
                        need(api("GET", "/accounts/" + row["id"]).status == 404, "fixture-cleanup-unconfirmed")
                        next(record for record in objects if record["kind"] == row["type"] + "-account"
                             and record["id"] == row["id"])["observation"] = "deleted-after-exact-read"
                    if objects:
                        metadata["lifecycle"] = "deleted"
                        self.evidence.set(target, "cleanup", code="exact-created-transaction-and-empty-accounts-deleted")
                except Exception:
                    clean = False
                    self.evidence.set(target, "cleanup", "failed", "exact-object-cleanup-unproven")
        return bool(objects) and clean

    def huly(self, context, page, app):
        """Native UI owns workspace-token handling; the harness NEVER exports it.

        The native account cookie is deliberately workspace-less in this version:
        use it ONLY for read-only getLoginInfoByToken/getUserWorkspaces. Project,
        task, workspace changes/deletes use the pinned UI and its in-memory
        native client, not fabricated HTTP endpoints or a bearer-token shim.
        Only explicit retain-created-for-restart-probe may mutate until the
        owning module supplies an exact native cleanup/confirmation hook.
        """
        target, root = app["id"], origin(app["url"])
        name = "P0-" + self.plan["runId"]  # native workspace name limit is 40
        project, task = "p0-project-" + self.plan["runId"], "p0-task-" + self.plan["runId"]
        description = "Synthetic browser fixture " + self.plan["runId"]
        workspace, project_id, task_id = None, None, None
        project_href, task_href = None, None
        phase, objects = "workflow", []
        metadata = self.fixture_metadata(app, objects)
        def rpc(method):
            need(method in ("getLoginInfoByToken", "getUserWorkspaces"), "huly-rpc-scope-refused")
            need(origin(page.url) == root, "wrong-app-origin")
            cookies = [c for c in context.cookies([root + "/_accounts"]) if c["name"] == "account-metadata-Token"]
            need(len(cookies) == 1 and cookies[0].get("secure") and cookies[0].get("httpOnly"),
                 "huly-native-cookie-session-unproven")
            result = self.body(self.api(context, "POST", root + "/_accounts", data={"method": method, "params": {}},
                headers={"Content-Type": "application/json", "Origin": root, "Referer": app["url"]}))
            need(isinstance(result, dict) and "error" not in result and "result" in result,
                 "huly-native-cookie-session-unproven")
            return result["result"]
        def click(css):
            self.ui(page, app, css).click()
        def fill(css, text):
            self.ui(page, app, css).fill(text)
        def input_is(css, expected):
            need(self.ui(page, app, css).input_value() == expected, "fixture-object-changed")
        def link(css):
            value = self.ui(page, app, css).get_attribute("href")
            need(isinstance(value, str), "missing-native-object-link")
            url = root + value if value.startswith("/") else value
            need(origin(url) == root and not urlsplit(url).query and not urlsplit(url).fragment,
                 "native-object-link-scope")
            return url
        def owned_workspace():
            rows = rpc("getUserWorkspaces")
            need(isinstance(rows, list), "huly-native-cookie-session-unproven")
            matches = [row for row in rows if row.get("uuid") == workspace["uuid"]]
            need(len(matches) == 1 and all(matches[0].get(k) == workspace[k] for k in ("name", "url")),
                 "fixture-workspace-changed")
            need(urlsplit(page.url).path.startswith("/workbench/" + workspace["url"] + "/"),
                 "fixture-workspace-scope")
        def project_button():
            return 'button.hulyNavGroup-header span:text-is("' + project + '")'
        def project_action(action):
            owned_workspace()
            node = self.ui(page, app, project_button())
            node.hover()
            self.binding.check()
            node.locator('xpath=../..').locator('div[class*="tools"] button').click()
            click('div.selectPopup button.menu-item:text-is("' + action + '")')
        def open_project():
            owned_workspace()
            click(project_button())
            return link('button.hulyNavGroup-header:has(span:text-is("' + project + '"))'
                        ' + div a[href*="issues"]')
        def open_task():
            self.visit(page, target, task_href)
            owned_workspace()
            input_is('div.popupPanel-body input[type="text"]', task)
            need(self.ui(page, app, 'div.popupPanel-body div.textInput div.tiptap').inner_text().strip() == description,
                 "fixture-object-changed")
        try:
            need(app["workflow"]["cleanup"] == "retain-created-for-restart-probe",
                 "huly-native-exact-cleanup-hook-required")
            subject = self.native_subject(app)
            login = rpc("getLoginInfoByToken")
            need(isinstance(login, dict) and login.get("account") == subject, "huly-native-account-mismatch")
            before = rpc("getUserWorkspaces")
            need(isinstance(before, list) and not any(row.get("name") == name for row in before), "fixture-already-exists")
            self.visit(page, target, root + "/login/createWorkspace")
            fill('input[name="workspace"]', name)
            click('div.form-row button')
            # Native workspace provisioning is asynchronous; no substitute setup
            # wizard, guessed API success or extension of the global run lease.
            self.ui(page, app, 'button[id$="TrackerApplication"]').wait_for(state="visible")
            rows = rpc("getUserWorkspaces")
            matches = [row for row in rows if row.get("name") == name]
            need(len(matches) == 1, "huly-native-workspace-permission-unproven")
            workspace = {key: matches[0][key] for key in ("uuid", "name", "url")}
            need(isinstance(workspace["uuid"], str) and UUID.fullmatch(workspace["uuid"])
                 and isinstance(workspace["url"], str) and re.fullmatch(r"[a-z0-9-]{1,100}", workspace["url"])
                 and not any(row.get("uuid") == workspace["uuid"] for row in before), "invalid-created-workspace")
            objects.append({"kind": "workspace", "id": workspace["uuid"], "sha256": self.value_sha(workspace)})
            owned_workspace()
            click('button[id$="TrackerApplication"]')
            # Selectors are the upstream v0.7.423 sanity page objects, not a
            # generic dashboard or caller-supplied mutation script.
            self.ui(page, app, '#navGroup-tree-projects').locator('xpath=../button[1]').hover()
            click('#tree-projects')
            fill('div[id="project-title"] input', project)
            fill('div[id="project-identifier"] input', "P0" + self.plan["runId"][:4].upper())
            fill('div[id="project-description"] input', description)
            click('form[id="tracker:string:NewProject"] button[type="submit"]')
            project_href = open_project()
            match = re.fullmatch(r"/workbench/" + re.escape(workspace["url"]) + r"/tracker/([^/]+)/issues", urlsplit(project_href).path)
            need(match is not None and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", match[1]), "invalid-created-project")
            project_id = match[1]
            objects.append({"kind": "project", "id": project_id, "sha256": self.value_sha([project, description])})
            project_action("Edit project")
            input_is('form[id="tracker:string:EditProject"] div[id="project-title"] input', project)
            input_is('form[id="tracker:string:EditProject"] div[id="project-description"] input', description)
            fill('form[id="tracker:string:EditProject"] div[id="project-description"] input', description + " changed")
            click('form[id="tracker:string:EditProject"] button[type="submit"]')
            project_action("Edit project")
            input_is('form[id="tracker:string:EditProject"] div[id="project-description"] input', description + " changed")
            click('form[id="tracker:string:EditProject"] button[type="submit"]')
            objects[-1]["sha256"] = self.value_sha([project, description + " changed"])
            self.visit(page, target, project_href)
            owned_workspace()
            click('#tracker-string-NewIssue')
            fill('form[id="tracker:string:NewIssue"] input[type="text"]', task)
            fill('form[id="tracker:string:NewIssue"] div.tiptap', description)
            click('button > span:text-is("Create issue")')
            task_href = link('div.listGrid a:text-is("' + task + '")')
            need(urlsplit(task_href).path.startswith("/workbench/" + workspace["url"] + "/tracker/"),
                 "invalid-created-task")
            task_id = urlsplit(task_href).path.rsplit("/", 1)[-1]
            need(re.fullmatch(r"[A-Za-z0-9_-]{1,100}", task_id), "invalid-created-task")
            objects.append({"kind": "task", "id": task_id, "sha256": self.value_sha([task, description])})
            open_task()
            fill('div.popupPanel-body input[type="text"]', task + "-changed")
            self.binding.check()
            page.keyboard.press("Tab")  # Native field blur commits the edit.
            task += "-changed"
            open_task()
            objects[-1]["sha256"] = self.value_sha([task, description])
            # Change workspace name ONLY after pinning its UUID and exclusive
            # path. General.svelte's .ws editor is source-backed and owner-only.
            settings_url = root + "/workbench/" + workspace["url"] + "/setting/workspace/general"
            self.visit(page, target, settings_url)
            owned_workspace()
            input_is('.ws .editBox input', workspace["name"])
            click('.ws > button')
            fill('.ws .editBox input', name + "-x")
            # When editing, the second button is cancel: select the first
            # source-owned direct Button, never a generic page-wide submit.
            self.binding.check()
            page.locator('.ws > button').first.click()
            workspace["name"] = name + "-x"
            owned_workspace()
            objects[0]["sha256"] = self.value_sha(workspace)
            self.evidence.set(target, "workflow", code="native-browser-workspace-project-task-create-read-change")
            phase = "persistence"
            page.reload(wait_until="domcontentloaded")
            self.authenticated(page, app, self.secret["member"])
            owned_workspace()
            input_is('.ws .editBox input', workspace["name"])
            open_task()
            self.evidence.set(target, "persistence", code="read-after-browser-reload-only")
        except Refused as exc:
            self.evidence.set(target, phase, "unproven" if str(exc) in PREREQUISITES else "failed",
                              str(exc) if str(exc) in PREREQUISITES else "native-ui-object-roundtrip-failed")
        except Exception:
            self.evidence.set(target, phase, "failed", "native-ui-object-roundtrip-failed")
        finally:
            if app["workflow"]["cleanup"] == "retain-created-for-restart-probe":
                metadata["lifecycle"] = "retained-by-explicit-plan"
                self.evidence.set(target, "cleanup", "unproven", "retained-for-authorized-restart-probe")
            else:
                # Do not schedule a destructive operation whose completion the
                # public native session cannot establish. Never substitute the
                # filtered workspace list, archive, UI detach, or a fake RPC for
                # an exact graph/owner/deletion observation by the owning module.
                self.evidence.set(target, "cleanup", "unproven", "huly-native-exact-cleanup-hook-required")
        return workspace is not None

    def firefly(self, context, page, app):
        token = self.secret.get("firefly", {}).get(app["id"])
        email = self.secret["member"].get("email")
        if not isinstance(token, str) or not token or not isinstance(email, str) or not email:
            return False  # An absent PAT is never a workflow pass.
        base = origin(app["url"]) + "/api/v1"
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        def api(method, path, **kw):
            return self.api(context, method, base + path, headers=headers, **kw)
        user = self.body(api("GET", "/about/user"))
        need(user["data"]["attributes"]["email"] == email, "api-actor-mismatch")
        name = "p0-browser-" + self.plan["runId"]
        # No updates to existing accounts, categories, transactions, or balances.
        created = self.body(api("POST", "/accounts", data={"name": name, "type": "asset",
                              "account_role": "defaultAsset", "opening_balance": "0"}), (200, 201))
        object_id = created["data"]["id"]
        need(isinstance(object_id, str) and re.fullmatch(r"[1-9][0-9]*", object_id), "invalid-created-id")
        path = "/accounts/" + object_id
        def owned():
            data = self.body(api("GET", path))["data"]
            need(data["id"] == object_id and data["attributes"]["name"] == name
                 and data["attributes"]["type"] == "asset", "fixture-object-changed")
        phase = "workflow"
        try:
            owned()
            self.evidence.set(app["id"], "workflow", code="browser-sso-and-api-create-read")
            phase = "persistence"
            page.reload(wait_until="domcontentloaded")
            self.authenticated(page, app, self.secret["member"])
            owned()
            self.evidence.set(app["id"], "persistence", code="read-after-browser-reload-only")
        except Exception:
            self.evidence.set(app["id"], phase, "failed", "object-roundtrip-failed")
        finally:
            try:
                owned()  # CAS + exact per-run object check before narrowly scoped delete.
                need(api("DELETE", path).status == 204, "fixture-cleanup-failed")
                need(api("GET", path).status == 404, "fixture-cleanup-unconfirmed")
                self.evidence.set(app["id"], "cleanup", code="exact-created-object-deleted")
            except Exception:
                self.evidence.set(app["id"], "cleanup", "failed", "exact-object-cleanup-unproven")
        return True

    def jupyterhub(self, context, page, app):
        self.visit(page, app["id"], app["server_url"])
        need(origin(page.url) == origin(app["server_url"])
             and urlsplit(page.url).path.startswith(urlsplit(app["server_url"]).path), "server-not-ready")
        path = app["server_url"] + "api/contents/p0-browser-" + self.plan["runId"] + ".ipynb"
        xsrf = [c["value"] for c in context.cookies([path]) if c["name"] == "_xsrf"]
        need(len(xsrf) == 1, "jupyter-xsrf-unproven")
        headers = {"X-XSRFToken": xsrf[0]}
        notebook = {"nbformat": 4, "nbformat_minor": 5, "metadata": {}, "cells": [
            {"cell_type": "markdown", "id": self.plan["runId"], "metadata": {},
             "source": "Synthetic browser fixture " + self.plan["runId"]}]}
        def api(method, **kw):
            return self.api(context, method, path, headers=headers, **kw)
        need(api("GET").status == 404, "fixture-already-exists")
        self.body(api("PUT", data={"type": "notebook", "format": "json", "content": notebook}), (201,))
        def owned():
            data = self.body(api("GET"))
            need(data["type"] == "notebook" and data["content"] == notebook, "fixture-object-changed")
        phase = "workflow"
        try:
            owned()
            self.evidence.set(app["id"], "workflow", code="browser-cookie-notebook-create-read")
            phase = "persistence"
            page.reload(wait_until="domcontentloaded")
            owned()
            self.evidence.set(app["id"], "persistence", code="read-after-browser-reload-only")
        except Exception:
            self.evidence.set(app["id"], phase, "failed", "object-roundtrip-failed")
        finally:
            try:
                owned()
                need(api("DELETE").status == 204, "fixture-cleanup-failed")
                need(api("GET").status == 404, "fixture-cleanup-unconfirmed")
                self.evidence.set(app["id"], "cleanup", code="exact-created-object-deleted")
            except Exception:
                self.evidence.set(app["id"], "cleanup", "failed", "exact-object-cleanup-unproven")
        return True

    def deny(self, app, context):
        if "denial" not in app:
            return
        page = context.new_page()
        denial = app["denial"]
        response = self.visit(page, app["id"], denial["url"])
        need(response.status in (401, 403) and origin(page.url) == origin(app["url"]),
             "role-denial-not-observed")
        page.locator(denial["selector"]).wait_for(state="visible")
        need(page.locator(app["authenticated_selector"]).count() == 0, "denied-app-accessible")
        self.evidence.set(app["id"], "role_denial", code="distinct-browser-actor-denied")
        page.close()

    def logout(self, context):
        kc = self.plan["keycloak"]
        page = context.new_page()
        self.binding.check()
        page.goto(kc["logout_url"], wait_until="domcontentloaded")
        need(origin(page.url) == kc["url"], "logout-origin-refused")
        page.locator(kc["logout_selector"]).click()
        for config in [dict(self.plan["portal"], id="portal")] + self.plan["apps"]:
            name = config["id"]
            try:
                self.visit(page, name, config["url"])
                page.wait_for_url(lambda url: origin(str(url)) == kc["url"])
                page.locator("#username").wait_for(state="visible")
                page.locator("#password").wait_for(state="visible")
                self.evidence.set(name, "logout", code="existing-context-requires-keycloak-login")
            except Exception:
                self.evidence.set(name, "logout", "failed", "session-remained-or-logout-unproven")
        page.close()

    def run(self):
        try:
            member = self.context()
            self.portal_login(member, self.secret["member"])
            for app in self.plan["apps"]:
                name, phase = app["id"], "sso"
                page = member.new_page()
                try:
                    self.visit(page, name, app["url"])
                    if "sso_selector" in app:
                        page.locator(app["sso_selector"]).click()
                    # No credential fill, native-app login, token grant, or cookie injection here.
                    self.authenticated(page, app, self.secret["member"])
                    self.evidence.set(name, "readiness")
                    self.evidence.set(name, "sso", code="same-browser-context-no-second-login")
                    phase = "workflow"
                    driver = {"firefly": self.firefly, "firefly-iii": self.firefly_iii,
                              "huly": self.huly, "jupyterhub": self.jupyterhub}.get(app["driver"])
                    if driver is not None:
                        driver(member, page, app)
                except Exception:
                    self.evidence.set(name, phase, "failed", "browser-or-protocol-check-failed")
                finally:
                    page.close()
            denied = self.context()
            try:
                self.portal_login(denied, self.secret["denied"])
                for app in self.plan["apps"]:
                    try:
                        self.deny(app, denied)
                    except Exception:
                        self.evidence.set(app["id"], "role_denial", "failed", "denial-check-failed")
            except Exception:
                for app in self.plan["apps"]:
                    self.evidence.set(app["id"], "role_denial", "failed", "denied-actor-login-failed")
            self.logout(member)
            self.binding.check()
        except Exception:
            self.evidence.set("portal", "sso", "failed", "run-interrupted-or-authority-changed")
        finally:
            for context in self.contexts:
                context.close()
        return self.evidence.result()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--expect-plan-sha256", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--credentials-file")
    group.add_argument("--credentials-fd", type=int)
    parser.add_argument("--timeout", type=int, default=110, choices=range(1, 121))
    args = parser.parse_args()
    binding = None
    def deadline(_signum, _frame):
        if binding is not None:
            binding.cancelled = True
        raise Refused("run-deadline")
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(args.timeout)
    try:
        reader = ProtectedReader()
        binding = Binding(reader, args.plan, args.expect_plan_sha256)
        secret = credentials(reader, args.credentials_file, args.credentials_fd)
        # Driver debug logging can include typed credentials: do not inherit env.
        # Executable lookup must be supplied by the isolated launcher's PATH/HOME;
        # only Playwright's standard runtime-location variables survive.
        allowed = ("PATH", "HOME", "PLAYWRIGHT_BROWSERS_PATH", "TMPDIR", "LANG", "LC_ALL")
        runtime_environment = {k: os.environ[k] for k in allowed if k in os.environ}
        os.environ.clear()
        os.environ.update(runtime_environment)
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            with playwright.chromium.launch(headless=True, chromium_sandbox=True) as browser:
                report = Harness(binding, secret, browser).run()
        print(json.dumps(report, sort_keys=True))
        return 0 if report["browserScopesPassed"] else 2
    except Exception:
        # Never emit exception strings, request URLs, response bodies or tracebacks.
        print(json.dumps({"schemaVersion": 1, "scope": "host-synthetic-browser",
                          "browserScopesPassed": False, "completeAcceptance": False,
                          "state": "refused", "code": "input-runtime-or-authority-unproven"}))
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
