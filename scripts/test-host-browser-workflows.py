#!/usr/bin/env python3
"""Offline stdlib mocks only. No browser, network, host API, or privileged calls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).with_name("verify-host-browser-workflows.py")
spec = importlib.util.spec_from_file_location("host_browser_workflows", SOURCE)
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
NOW = 1700000000
RUN = "a" * 32
STATE = "/native"
RELEASE = STATE + "/releases/selected"
PINS = {key: "b" * 64 for key in ("bundle.json", "stack.ir.json", "source-provenance.json")}


def plan():
    return {"schemaVersion": 1, "scope": "host-synthetic-browser", "exclusiveFixture": True,
            "runId": RUN, "fixtureId": "browser-fixture", "issuedAt": NOW - 1,
            "expiresAt": NOW + 300, "stateRoot": STATE, "release": RELEASE,
            "selectedApps": ["firefly", "jupyterhub"],
            "marker": {"path": "/marker.json", "sha256": "b" * 64},
            "journal": {"path": STATE + "/.install-intent.json", "sha256": "b" * 64},
            "receipt": {"path": RELEASE + "/installation-receipt.json", "sha256": "b" * 64},
            "keycloak": {"url": "https://auth.fixture.test", "realm": "fixture",
                         "logout_url": "https://auth.fixture.test/realms/fixture/account/",
                         "logout_selector": "#sign-out"},
            "portal": {"url": "https://portal.fixture.test/", "authenticated_selector": "#app",
                       "identity_selector": "#identity"},
            "apps": [{"id": "firefly", "driver": "firefly", "url": "https://firefly.fixture.test/",
                      "authenticated_selector": "#app", "identity_selector": "#identity",
                      "denial": {"url": "https://firefly.fixture.test/", "selector": "#forbidden"}},
                     {"id": "jupyterhub", "driver": "jupyterhub", "url": "https://jupyter.fixture.test/hub/",
                      "server_url": "https://jupyter.fixture.test/user/member/",
                      "authenticated_selector": "#app", "identity_selector": "#identity",
                      "denial": {"url": "https://jupyter.fixture.test/hub/", "selector": "#forbidden"}}]}


def secrets():
    return {"member": {"username": "fixture-member", "password": "SYNTHETIC-MEMBER-SECRET",
                       "identity": "Fixture Member", "email": "member@fixture.test"},
            "denied": {"username": "fixture-denied", "password": "SYNTHETIC-DENIED-SECRET",
                       "identity": "Fixture Denied"}, "firefly": {"firefly": "SYNTHETIC-API-SECRET"}}


class AuthorityFixture:
    def __init__(self):
        # All mutable filesystem fixtures remain inside the delegated checkout.
        self.temp = tempfile.TemporaryDirectory(prefix=".browser-test-", dir=SOURCE.parent)
        self.root = Path(self.temp.name)
        self.reader = h.ProtectedReader(str(self.root), os.geteuid())
        self.plan = plan()
        receipt = {"schemaVersion": 1, "phase": "active", "release": RELEASE, "inputs": PINS}
        marker = {"schemaVersion": 1, "scope": "host-synthetic-browser",
                  "fixtureId": self.plan["fixtureId"], "selectedApps": self.plan["selectedApps"]}
        for key, path, value in (("marker", "/marker.json", marker),
                                 ("journal", STATE + "/.install-intent.json", receipt),
                                 ("receipt", RELEASE + "/installation-receipt.json", receipt)):
            raw = self.put(path, value)
            self.plan[key] = {"path": path, "sha256": h.digest(raw)}
        self.publish()

    def put(self, path, value):
        raw = json.dumps(value).encode() if not isinstance(value, bytes) else value
        target = self.root / path.lstrip("/")
        parent = self.root
        for part in target.relative_to(self.root).parts[:-1]:
            parent /= part
            parent.mkdir(mode=0o700, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o600)
        return raw

    def publish(self):
        self.sha = h.digest(self.put("/plan.json", self.plan))

    def binding(self):
        with patch.object(h.time, "time", return_value=NOW):
            return h.Binding(self.reader, "/plan.json", self.sha)

    def close(self):
        self.temp.cleanup()


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.f = AuthorityFixture()
        self.addCleanup(self.f.close)
        self.clock = patch.object(h.time, "time", return_value=NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def test_valid_cas_and_no_installer_mutation(self):
        before = {p: p.read_bytes() for p in self.f.root.rglob("*") if p.is_file()}
        self.f.binding().check()
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_plan_hash_required_before_decode(self):
        with self.assertRaises(h.Refused):
            h.Binding(self.f.reader, "/plan.json", "0" * 64)

    def test_cas_each_authority_and_plan(self):
        for key in ("plan", "marker", "journal", "receipt"):
            with self.subTest(key=key):
                binding = self.f.binding()
                path = "/plan.json" if key == "plan" else self.f.plan[key]["path"]
                original = (self.f.root / path.lstrip("/")).read_bytes()
                self.f.put(path, original + b" ")
                with self.assertRaises(h.Refused):
                    binding.check()
                self.f.put(path, original)

    def test_selection_order_omission_and_scope(self):
        for field, value in (("selectedApps", ["firefly"]), ("selectedApps", ["jupyterhub", "firefly"]),
                             ("scope", "production"), ("exclusiveFixture", False), ("expiresAt", NOW - 2),
                             ("expiresAt", NOW + 2000), ("schemaVersion", True)):
            with self.subTest(field=field, value=value):
                item = copy.deepcopy(self.f.plan)
                item[field] = value
                with self.assertRaises(h.Refused):
                    h.validate_plan(item, NOW)

    def test_active_matching_installer_receipt_required(self):
        for field, value in (("phase", "failed"), ("release", "/elsewhere"), ("inputs", {})):
            original = self.f.plan.copy()
            receipt = {"schemaVersion": 1, "phase": "active", "release": RELEASE,
                       "inputs": PINS, field: value}
            for key in ("journal", "receipt"):
                raw = self.f.put(self.f.plan[key]["path"], receipt)
                self.f.plan[key] = dict(self.f.plan[key], sha256=h.digest(raw))
            self.f.publish()
            with self.assertRaises(h.Refused):
                self.f.binding()
            self.f.plan = original

    def test_marker_not_generic_machine_or_production_permission(self):
        raw = self.f.put("/marker.json", {"schemaVersion": 1, "scope": "isolated-synthetic"})
        self.f.plan["marker"]["sha256"] = h.digest(raw)
        self.f.publish()
        with self.assertRaises(h.Refused):
            self.f.binding()

    def test_runtime_cancellation_prevents_further_authority_checks(self):
        binding = self.f.binding()
        binding.cancelled = True
        with self.assertRaises(h.Refused):
            binding.check()

    def test_release_journal_and_receipt_paths_must_be_exact(self):
        for key, value in (("release", "/other/releases/selected"),
                           ("release", STATE + "/releases/nested/child"),
                           ("stateRoot", "/other")):
            item = copy.deepcopy(self.f.plan)
            item[key] = value
            with self.assertRaises(h.Refused):
                h.validate_plan(item, NOW)
        item = copy.deepcopy(self.f.plan)
        item["journal"]["path"] = "/other/.install-intent.json"
        with self.assertRaises(h.Refused):
            h.validate_plan(item, NOW)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(h.Refused):
            h.decode(b'{"schemaVersion":1,"schemaVersion":1}')

    def test_regular_file_only_no_leaf_or_parent_symlinks(self):
        self.f.put("/real/file", b"{}")
        (self.f.root / "leaf").symlink_to("real/file")
        (self.f.root / "alias").symlink_to("real", target_is_directory=True)
        for path in ("/leaf", "/alias/file"):
            with self.assertRaises((OSError, h.Refused)):
                self.f.reader.read(path)

    def test_no_hardlinks_or_fifo(self):
        self.f.put("/original", b"{}")
        os.link(self.f.root / "original", self.f.root / "hardlink")
        os.mkfifo(self.f.root / "fifo", mode=0o600)
        for path in ("/original", "/hardlink", "/fifo"):
            with self.assertRaises(h.Refused):
                self.f.reader.read(path)

    def test_no_path_escape(self):
        for path in ("relative", "/../plan.json", "/./plan.json", "//plan.json", "/plan.json/"):
            with self.assertRaises(h.Refused):
                self.f.reader.read(path)

    def test_no_writable_parent_or_file(self):
        self.f.put("/dir/item", b"{}")
        (self.f.root / "dir").chmod(0o777)
        with self.assertRaises(h.Refused):
            self.f.reader.read("/dir/item")
        (self.f.root / "dir").chmod(0o700)
        (self.f.root / "dir/item").chmod(0o666)
        with self.assertRaises(h.Refused):
            self.f.reader.read("/dir/item")

    def test_wrong_owner_and_oversize(self):
        with self.assertRaises(h.Refused):
            h.ProtectedReader(str(self.f.root), os.geteuid() + 1).read("/plan.json")
        self.f.put("/large", b"x" * (h.LIMIT + 1))
        with self.assertRaises(h.Refused):
            self.f.reader.read("/large")

    def test_mutation_during_read_refused(self):
        self.f.put("/racy", b"{}")
        original = h.os.read
        def read(fd, size):
            result = original(fd, size)
            if result:
                (self.f.root / "racy").write_bytes(b"changed")
            return result
        with patch.object(h.os, "read", side_effect=read), self.assertRaises(h.Refused):
            self.f.reader.read("/racy")

    def test_credentials_file_and_inherited_fd(self):
        self.f.put("/credentials", secrets())
        self.assertEqual(h.credentials(self.f.reader, path="/credentials"), secrets())
        fd = os.open(self.f.root / "credentials", os.O_RDONLY)
        try:
            self.assertEqual(h.credentials(self.f.reader, fd=fd), secrets())
            (self.f.root / "credentials").chmod(0o644)
            with self.assertRaises(h.Refused):
                h.credentials(self.f.reader, fd=fd)
        finally:
            os.close(fd)

    def test_fd_pipe_and_same_actor_refused(self):
        r, w = os.pipe()
        try:
            with self.assertRaises(h.Refused):
                h.credentials(self.f.reader, fd=r)
        finally:
            os.close(r)
            os.close(w)
        secret = secrets()
        secret["denied"]["username"] = secret["member"]["username"]
        self.f.put("/credentials", secret)
        with self.assertRaises(h.Refused):
            h.credentials(self.f.reader, path="/credentials")

    def test_only_normal_https_no_secret_query_or_server_escape(self):
        invalid = ("http://app.fixture.test/", "https://127.0.0.1/", "https://localhost/",
                   "https://user:pass@app.fixture.test/", "https://app.fixture.test/?token=secret",
                   "https://app.fixture.test:8443/", "https://app.fixture.test/a/../b",
                   "https://app.fixture.test/%2e%2e", "https://app.fixture.test/\\other")
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(h.Refused):
                h.https_url(url)
        item = copy.deepcopy(self.f.plan)
        item["apps"][1]["server_url"] = "https://other.fixture.test/user/member/"
        with self.assertRaises(h.Refused):
            h.validate_plan(item, NOW)


class Response:
    def __init__(self, status, value=None):
        self.status, self.value = status, value
    def json(self):
        return copy.deepcopy(self.value)


class FakeBinding:
    def __init__(self, value):
        self.plan, self.origins, self.checks, self.changed = value, h.validate_plan(value, NOW), 0, False
        self.expected = h.digest(json.dumps(value).encode())
    def check(self):
        self.checks += 1
        h.need(not self.changed, "selection-cas-changed")


class Locator:
    def __init__(self, page, selector):
        self.page, self.selector = page, selector
    def visible(self):
        if self.selector in ("#username", "#password"):
            return self.page.at_kc_login()
        if self.selector == "#app":
            return self.page.authed()
        if self.selector == "#identity":
            return self.page.authed()
        if self.selector == "#forbidden":
            return self.page.context.actor == "denied" and not self.page.at_kc_login()
        return False
    def wait_for(self, state):
        h.need(self.visible(), "mock-selector-not-visible")
    def count(self):
        if self.selector == 'input[type="password"]:visible':
            return int(self.page.at_kc_login() or self.page.context.browser.native_login)
        return int(self.visible())
    def inner_text(self):
        h.need(self.visible())
        return self.page.context.browser.secret[self.page.context.actor]["identity"]
    def fill(self, text):
        h.need(self.page.at_kc_login(), "mock-native-fill-refused")
        self.page.context.browser.fills.append((self.page.url, self.selector))
        self.page.fields[self.selector] = text
    def click(self):
        browser = self.page.context.browser
        if self.selector == "#kc-login":
            for key in ("member", "denied"):
                actor = browser.secret[key]
                if self.page.fields == {"#username": actor["username"], "#password": actor["password"]}:
                    self.page.context.actor = key
                    self.page.url = browser.plan["portal"]["url"]
                    return
            raise AssertionError("mock invalid credentials")
        if self.selector == "#sign-out":
            if not browser.stale_logout:
                self.page.context.actor = None
            return
        if self.selector == "#sso":
            return
        raise AssertionError("unexpected mock click")


class Page:
    def __init__(self, context):
        self.context, self.url, self.fields = context, "about:blank", {}
    def at_kc_login(self):
        return self.url.startswith(self.context.browser.plan["keycloak"]["url"] + "/realms/fixture/login")
    def authed(self):
        return self.context.actor is not None and not self.at_kc_login() and (
            self.context.actor == "member" or h.origin(self.url) == "https://portal.fixture.test")
    def goto(self, url, **kwargs):
        self.url = url
        if h.origin(url) != self.context.browser.plan["keycloak"]["url"]:
            if self.context.actor is None:
                self.url = self.context.browser.plan["keycloak"]["url"] + "/realms/fixture/login"
            elif self.context.actor == "denied" and h.origin(url) != "https://portal.fixture.test":
                return Response(self.context.browser.deny_status)
        return Response(200)
    def wait_for_url(self, predicate):
        h.need(predicate(self.url), "mock-url-mismatch")
    def locator(self, selector):
        return Locator(self, selector)
    def reload(self, **kwargs):
        self.context.browser.reloads += 1
    def close(self):
        pass


class Request:
    def __init__(self, context):
        self.context = context
    def fetch(self, url, method, max_redirects, timeout, **kwargs):
        browser = self.context.browser
        assert max_redirects == 0 and timeout <= 10000
        browser.calls.append((method, url))
        firefly = h.origin(url) == "https://firefly.fixture.test"
        if firefly:
            assert kwargs["headers"]["Authorization"] == "Bearer " + browser.secret["firefly"]["firefly"]
            if url.endswith("/about/user"):
                return Response(200, {"data": {"attributes": {"email": browser.api_email}}})
            if method == "POST":
                if browser.api_redirect:
                    return Response(302)
                data = {"id": "17", "attributes": kwargs["data"]}
                browser.objects[url + "/17"] = data
                return Response(201, {"data": data})
        else:
            assert kwargs["headers"]["X-XSRFToken"] == "SYNTHETIC-XSRF"
            if method == "PUT":
                browser.objects[url] = kwargs["data"]
                return Response(201, kwargs["data"])
        if method == "GET":
            if url not in browser.objects:
                return Response(404)
            value = browser.objects[url]
            if browser.corrupt_object:
                value = {"id": "17", "attributes": {"name": "not-our-object", "type": "asset"}}
            return Response(200, {"data": value} if firefly else value)
        if method == "DELETE":
            del browser.objects[url]
            return Response(204)
        raise AssertionError("unexpected mock API operation")


class Context:
    def __init__(self, browser):
        self.browser, self.actor, self.request, self.closed = browser, None, Request(self), False
    def set_default_timeout(self, value):
        assert value <= 10000
    def set_default_navigation_timeout(self, value):
        assert value <= 10000
    def route(self, pattern, callback):
        self.route_handler = callback
    def new_page(self):
        return Page(self)
    def cookies(self, urls):
        return [{"name": "_xsrf", "value": "SYNTHETIC-XSRF"}] if self.browser.xsrf else []
    def close(self):
        self.closed = True


class Browser:
    def __init__(self, value, secret):
        self.plan, self.secret, self.contexts, self.calls, self.fills, self.objects = value, secret, [], [], [], {}
        self.native_login, self.stale_logout, self.api_redirect, self.corrupt_object = False, False, False, False
        self.deny_status, self.api_email, self.xsrf, self.reloads = 403, "member@fixture.test", True, 0
    def new_context(self, **kwargs):
        assert kwargs == {"service_workers": "block", "accept_downloads": False}
        context = Context(self)
        self.contexts.append(context)
        return context


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.secret = plan(), secrets()
        self.browser = Browser(self.plan, self.secret)
        self.binding = FakeBinding(self.plan)
        self.runner = h.Harness(self.binding, self.secret, self.browser)

    def row(self, report, target, scope):
        return next(r for r in report["checks"] if r["target"] == target and r["scope"] == scope)

    def test_real_algorithm_mock_shared_login_api_persistence_cleanup_denial_logout(self):
        report = self.runner.run()
        self.assertTrue(report["browserScopesPassed"], report)
        self.assertFalse(report["completeAcceptance"])
        self.assertEqual(report["recovery"]["state"], "unproven")
        self.assertEqual(report["visual"]["state"], "unproven")
        self.assertEqual(len(self.browser.fills), 4)  # Exactly one login per distinct actor.
        self.assertTrue(all(h.origin(url) == self.plan["keycloak"]["url"] for url, _ in self.browser.fills))
        self.assertFalse(self.browser.objects)
        self.assertEqual(self.browser.reloads, 2)
        self.assertEqual(len(self.browser.contexts), 2)
        self.assertTrue(all(c.closed for c in self.browser.contexts))
        self.assertGreater(self.binding.checks, len(self.browser.calls))
        serialized = json.dumps(report)
        for secret in (self.secret["member"]["password"], self.secret["denied"]["password"],
                       self.secret["member"]["email"], self.secret["firefly"]["firefly"], "SYNTHETIC-XSRF"):
            self.assertNotIn(secret, serialized)

    def test_missing_firefly_api_credentials_unproven_not_passed(self):
        del self.secret["firefly"]
        report = self.runner.run()
        self.assertFalse(report["browserScopesPassed"])
        self.assertEqual(self.row(report, "firefly", "workflow")["state"], "unproven")
        self.assertEqual(self.row(report, "firefly", "sso")["state"], "passed")

    def test_native_app_login_does_not_count_as_sso(self):
        self.browser.native_login = True
        report = self.runner.run()
        self.assertFalse(report["browserScopesPassed"])
        self.assertFalse(self.browser.calls)

    def test_api_identity_mismatch_never_creates_firefly_object(self):
        self.browser.api_email = "someone-else@fixture.test"
        report = self.runner.run()
        self.assertEqual(self.row(report, "firefly", "workflow")["state"], "failed")
        self.assertFalse(any(method == "POST" for method, _ in self.browser.calls))

    def test_api_redirect_not_followed_or_counted(self):
        self.browser.api_redirect = True
        report = self.runner.run()
        self.assertEqual(self.row(report, "firefly", "workflow")["state"], "failed")
        self.assertFalse(any(method == "DELETE" and "firefly" in url for method, url in self.browser.calls))

    def test_changed_object_never_deleted(self):
        self.browser.corrupt_object = True
        report = self.runner.run()
        self.assertFalse(report["browserScopesPassed"])
        self.assertEqual(self.row(report, "firefly", "cleanup")["state"], "failed")
        self.assertFalse(any(method == "DELETE" for method, _ in self.browser.calls))

    def test_jupyter_collision_never_overwritten_or_deleted(self):
        path = self.plan["apps"][1]["server_url"] + "api/contents/p0-browser-" + RUN + ".ipynb"
        original = {"type": "notebook", "content": {"unrelated": True}}
        self.browser.objects[path] = copy.deepcopy(original)
        report = self.runner.run()
        self.assertEqual(self.browser.objects[path], original)
        self.assertFalse(any(method == "PUT" for method, _ in self.browser.calls))
        self.assertEqual(self.row(report, "jupyterhub", "workflow")["state"], "failed")

    def test_jupyter_without_xsrf_no_mutation(self):
        self.browser.xsrf = False
        report = self.runner.run()
        self.assertEqual(self.row(report, "jupyterhub", "workflow")["state"], "failed")
        self.assertFalse(any(method == "PUT" for method, _ in self.browser.calls))

    def test_role_denial_requires_actual_denial_status(self):
        self.browser.deny_status = 200
        report = self.runner.run()
        for target in self.plan["selectedApps"]:
            self.assertEqual(self.row(report, target, "role_denial")["state"], "failed")

    def test_missing_denial_and_new_workflow_remain_unproven(self):
        app = self.plan["apps"][0]
        app["driver"] = "unimplemented"
        del app["denial"]
        report = self.runner.run()
        self.assertFalse(report["browserScopesPassed"])
        self.assertEqual(self.row(report, "firefly", "sso")["state"], "passed")
        for scope in ("workflow", "persistence", "cleanup", "role_denial"):
            self.assertEqual(self.row(report, "firefly", scope)["state"], "unproven")

    def test_native_sessions_after_logout_are_failures(self):
        self.browser.stale_logout = True
        report = self.runner.run()
        self.assertFalse(report["browserScopesPassed"])
        for target in ["portal"] + self.plan["selectedApps"]:
            self.assertEqual(self.row(report, target, "logout")["state"], "failed")

    def test_authority_change_prevents_all_network_and_mutations(self):
        self.binding.changed = True
        report = self.runner.run()
        self.assertFalse(report["browserScopesPassed"])
        self.assertFalse(self.browser.calls)
        self.assertFalse(self.browser.fills)

    def test_api_rechecks_cas_before_delete(self):
        context = self.runner.context()
        self.binding.changed = True
        with self.assertRaises(h.Refused):
            self.runner.api(context, "DELETE", "https://firefly.fixture.test/api/v1/accounts/17")
        self.assertFalse(self.browser.calls)

    def test_browser_route_blocks_external_or_insecure_requests(self):
        context = self.runner.context()
        class Route:
            def __init__(self, url):
                self.request = type("Request", (), {"url": url})()
                self.state = None
            def continue_(self):
                self.state = "allowed"
            def abort(self, code):
                self.state = "blocked"
        for url, expected in (("https://auth.fixture.test/realms/fixture/login?code=opaque", "allowed"),
                              ("https://external.fixture.test/", "blocked"),
                              ("http://portal.fixture.test/", "blocked"),
                              ("file:///etc/passwd", "blocked")):
            route = Route(url)
            context.route_handler(route)
            self.assertEqual(route.state, expected)

    def test_per_app_real_identity_labels_supported(self):
        actor = self.secret["member"]
        actor["identities"] = {"firefly": "member@fixture.test", "jupyterhub": "member"}
        page = self.runner.context().new_page()
        page.context.actor = "member"
        for app in self.plan["apps"]:
            page.url = app["url"]
            with patch.object(Locator, "inner_text", return_value=actor["identities"][app["id"]]):
                self.runner.authenticated(page, app, actor)

    def test_report_binds_exact_authority_hashes(self):
        report = self.runner.run()
        self.assertEqual(report["bindings"]["planSha256"], self.binding.expected)
        for key in ("marker", "journal", "receipt"):
            self.assertEqual(report["bindings"][key + "Sha256"], self.plan[key]["sha256"])

    def test_transport_failure_is_not_readiness_or_sso_success(self):
        context = self.runner.context()
        page = context.new_page()
        with patch.object(page, "goto", side_effect=RuntimeError("synthetic TLS failure")):
            with self.assertRaises(RuntimeError):
                self.runner.visit(page, "firefly", self.plan["apps"][0]["url"])
        report = self.runner.evidence.result()
        self.assertEqual(self.row(report, "firefly", "transport")["state"], "failed")
        self.assertEqual(self.row(report, "firefly", "readiness")["state"], "unproven")
        self.runner.evidence.set("firefly", "transport")
        self.assertEqual(self.row(self.runner.evidence.result(), "firefly", "transport")["state"], "failed")

    def test_http_503_transport_only_not_ready(self):
        page = self.runner.context().new_page()
        with patch.object(page, "goto", return_value=Response(503)), self.assertRaises(h.Refused):
            self.runner.visit(page, "firefly", self.plan["apps"][0]["url"])
        report = self.runner.evidence.result()
        self.assertEqual(self.row(report, "firefly", "transport")["state"], "passed")
        self.assertEqual(self.row(report, "firefly", "readiness")["state"], "failed")

    def test_sso_rechallenge_never_types_second_credentials(self):
        self.runner.portal_login(self.runner.context(), self.secret["member"])
        page = self.browser.contexts[0].new_page()
        page.url = self.plan["keycloak"]["url"] + "/realms/fixture/login"
        with self.assertRaises(h.Refused):
            self.runner.authenticated(page, self.plan["apps"][0], self.secret["member"])
        self.assertEqual(len(self.browser.fills), 2)

    def test_persistence_failure_does_not_erase_workflow_or_cleanup(self):
        with patch.object(Page, "reload", side_effect=RuntimeError("synthetic reload failure")):
            report = self.runner.run()
        for target in self.plan["selectedApps"]:
            self.assertEqual(self.row(report, target, "workflow")["state"], "passed")
            self.assertEqual(self.row(report, target, "persistence")["state"], "failed")
            self.assertEqual(self.row(report, target, "cleanup")["state"], "passed")
        self.assertFalse(self.browser.objects)

    def test_cas_failure_after_create_leaves_object_not_unrelated_cleanup(self):
        context = self.runner.context()
        self.runner.portal_login(context, self.secret["member"])
        page = context.new_page()
        self.runner.visit(page, "firefly", self.plan["apps"][0]["url"])
        def changed(**kwargs):
            self.binding.changed = True
        with patch.object(page, "reload", side_effect=changed):
            self.runner.firefly(context, page, self.plan["apps"][0])
        self.assertTrue(self.browser.objects)
        self.assertFalse(any(method == "DELETE" for method, _ in self.browser.calls))
        report = self.runner.evidence.result()
        self.assertEqual(self.row(report, "firefly", "cleanup")["state"], "failed")

    def test_no_response_or_exception_secret_in_report(self):
        def fail(*args, **kwargs):
            raise RuntimeError("SYNTHETIC-MEMBER-SECRET SYNTHETIC-API-SECRET")
        with patch.object(self.runner, "firefly", side_effect=fail):
            report = self.runner.run()
        self.assertNotIn("SECRET", json.dumps(report))


SUBJECT = "12345678-1234-1234-1234-123456789abc"


def native_plan(driver):
    value = plan()
    app = copy.deepcopy(value["apps"][0])
    app.update(id=driver, driver=driver, url="https://" + driver + ".fixture.test/")
    app["workflow"] = {"kind": h.WORKFLOWS[driver], "cleanup": "delete-created"}
    if driver == "firefly-iii":
        app["workflow"].update(currency="EUR", date="2026-10-24")
    else:
        app["workflow"]["language"] = "en"
    app.pop("denial")
    value["apps"], value["selectedApps"] = [app], [driver]
    return value


class NativeFireflyPage(Page):
    def locator(self, css):
        if css == 'meta[name="csrf-token"]':
            return SimpleNamespace(count=lambda: int(self.context.backend.csrf),
                                   get_attribute=lambda key: "SYNTHETIC-NATIVE-CSRF")
        return super().locator(css)


class NativeFireflyAPI:
    """App API boundary model ONLY, not an HTTP-success/installed proof."""
    def __init__(self, runner):
        self.runner, self.objects, self.calls, self.counter = runner, {}, [], 10
        self.csrf, self.cookie, self.subject, self.redirect = True, True, SUBJECT, False
        self.foreign_children, self.corrupt, self.after = False, False, lambda *args: None

    def fetch(self, url, method, max_redirects, timeout, **kw):
        assert max_redirects == 0 and timeout == 7000
        assert h.origin(url) == self.runner.plan["apps"][0]["url"].rstrip("/")
        assert "Authorization" not in kw["headers"]
        assert kw["headers"]["X-CSRF-TOKEN"] == "SYNTHETIC-NATIVE-CSRF"
        self.calls.append((method, url, copy.deepcopy(kw.get("data"))))
        path = url.split("/api/v1", 1)[1]
        if path == "/about/user":
            return Response(200, {"data": {"attributes": {"email": self.subject}}})
        if method == "POST":
            if self.redirect:
                return Response(302)
            self.counter += 1
            data = copy.deepcopy(kw["data"])
            if path == "/transactions":
                assert data["apply_rules"] is False and data["fire_webhooks"] is False
                attrs = {"transactions": data["transactions"]}
                attrs["transactions"][0]["transaction_journal_id"] = "99"
            else:
                assert path == "/accounts"
                attrs = data
            value = {"id": str(self.counter), "attributes": attrs}
            self.objects[path + "/" + value["id"]] = value
            self.after(method, path)
            return Response(201, {"data": value})
        if path.endswith("/transactions") and path.startswith("/accounts/"):
            assert method == "GET"
            count = 1 if self.foreign_children or any(p.startswith("/transactions/") for p in self.objects) else 0
            return Response(200, {"data": [{"id": "unrelated"}] if count else [],
                                  "meta": {"pagination": {"total": count}}})
        if path not in self.objects:
            return Response(404)
        value = self.objects[path]
        if method == "PUT":
            data = kw["data"]
            if path.startswith("/transactions/"):
                assert data["apply_rules"] is False and data["fire_webhooks"] is False
                assert data["transactions"][0]["transaction_journal_id"] == "99"
                value["attributes"]["transactions"][0].update(data["transactions"][0])
            else:
                value["attributes"].update(data)
            self.after(method, path)
            return Response(200, {"data": value})
        if method == "GET":
            result = copy.deepcopy(value)
            if self.corrupt and path.startswith("/accounts/"):
                result["attributes"]["notes"] = "unrelated authored state"
            return Response(200, {"data": result})
        assert method == "DELETE"
        del self.objects[path]
        return Response(204)


class NativeWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.plan = native_plan("firefly-iii")
        self.secret = secrets()
        self.secret["member"]["nativeSubjects"] = {"firefly-iii": SUBJECT, "huly": SUBJECT}
        self.binding = FakeBinding(self.plan)
        self.browser = Browser(self.plan, self.secret)
        self.runner = h.Harness(self.binding, self.secret, self.browser)
        self.backend = NativeFireflyAPI(self.runner)
        self.context = Context(self.browser)
        self.context.actor = "member"
        self.context.backend = self.backend
        self.context.request = self.backend
        self.context.cookies = lambda urls: ([{"name": name, "value": "SYNTHETIC-NATIVE-COOKIE",
            "secure": True, "httpOnly": True} for name in ("__Host-firefly_app", "laravel_token")]
            if self.backend.cookie else [])
        self.page = NativeFireflyPage(self.context)
        self.page.url = self.plan["apps"][0]["url"]

    def run_firefly(self):
        self.runner.firefly_iii(self.context, self.page, self.plan["apps"][0])
        return self.runner.evidence.result()

    def row(self, report, scope):
        return next(row for row in report["checks"] if row["target"] == "firefly-iii" and row["scope"] == scope)

    def test_native_cookie_accounts_and_withdrawal_create_read_change_cleanup_model(self):
        report = self.run_firefly()
        for scope in ("workflow", "persistence", "cleanup"):
            self.assertEqual(self.row(report, scope)["state"], "passed", report)
        self.assertFalse(self.backend.objects)
        self.assertEqual(sum(method == "POST" for method, _, _ in self.backend.calls), 3)
        self.assertEqual(sum(method == "PUT" for method, _, _ in self.backend.calls), 3)
        self.assertEqual(sum(method == "DELETE" for method, _, _ in self.backend.calls), 3)
        self.assertGreater(self.binding.checks, len(self.backend.calls))
        fixture = report["fixtures"][0]
        self.assertEqual(fixture["lifecycle"], "deleted")
        self.assertEqual([row["kind"] for row in fixture["objects"]], ["asset-account", "expense-account", "withdrawal"])
        self.assertTrue(all(h.HEX.fullmatch(row["sha256"]) for row in fixture["objects"]))
        self.assertFalse(report["browserScopesPassed"])  # no SSO/denial/logout proof in a driver model
        self.assertEqual(report["durablePersistence"]["state"], "unproven")

    def test_new_driver_uses_no_pat_even_if_legacy_pat_missing(self):
        del self.secret["firefly"]
        report = self.run_firefly()
        self.assertEqual(self.row(report, "workflow")["state"], "passed")

    def test_missing_subject_cookie_or_csrf_is_specific_unproven_without_mutation(self):
        for missing in ("subject", "cookie", "csrf"):
            with self.subTest(missing=missing):
                self.setUp()
                if missing == "subject":
                    del self.secret["member"]["nativeSubjects"]
                else:
                    setattr(self.backend, missing, False)
                report = self.run_firefly()
                self.assertEqual(self.row(report, "workflow")["state"], "unproven")
                self.assertIn(self.row(report, "workflow")["code"], h.PREREQUISITES)
                self.assertFalse(self.backend.calls)

    def test_insecure_script_readable_or_ambiguous_native_cookie_refused(self):
        cookie_source = self.context.cookies
        original = cookie_source([])
        for variant in (dict(original[0], secure=False), dict(original[0], httpOnly=False), None):
            with self.subTest(variant=variant):
                cookies = [variant, original[1]] if variant else original + [dict(original[0], secure=False)]
                self.context.cookies = lambda urls: cookies
                report = self.run_firefly()
                self.assertEqual(self.row(report, "workflow")["state"], "unproven")
                self.assertFalse(self.backend.calls)

    def test_known_created_id_retained_in_metadata_when_initial_read_pin_fails(self):
        def foreign(method, path):
            if method == "POST":
                next(iter(self.backend.objects.values()))["attributes"]["notes"] = "foreign state"
        self.backend.after = foreign
        report = self.run_firefly()
        fixture = report["fixtures"][0]["objects"]
        self.assertEqual(len(fixture), 1)
        self.assertEqual(fixture[0]["id"], "11")
        self.assertEqual(fixture[0]["observation"], "created-id-only")
        self.assertEqual(self.row(report, "cleanup")["state"], "failed")
        self.assertFalse(any(method == "DELETE" for method, _, _ in self.backend.calls))

    def test_native_subject_mismatch_cannot_create_anything(self):
        self.backend.subject = "other-subject"
        report = self.run_firefly()
        self.assertEqual(self.row(report, "workflow")["state"], "failed")
        self.assertFalse(any(method == "POST" for method, _, _ in self.backend.calls))

    def test_native_redirect_never_followed_or_adopted(self):
        self.backend.redirect = True
        report = self.run_firefly()
        self.assertEqual(self.row(report, "workflow")["state"], "failed")
        self.assertFalse(any(method == "DELETE" for method, _, _ in self.backend.calls))

    def test_changed_account_never_deleted(self):
        self.backend.corrupt = True
        report = self.run_firefly()
        self.assertEqual(self.row(report, "cleanup")["state"], "failed")
        self.assertFalse(any(method == "DELETE" for method, _, _ in self.backend.calls))
        self.assertTrue(self.backend.objects)

    def test_unknown_account_transactions_block_cascading_account_cleanup(self):
        self.backend.foreign_children = True
        report = self.run_firefly()
        self.assertEqual(self.row(report, "workflow")["state"], "passed")
        self.assertEqual(self.row(report, "cleanup")["state"], "failed")
        self.assertEqual(sum(method == "DELETE" for method, _, _ in self.backend.calls), 1)
        self.assertEqual(len(self.backend.objects), 2)

    def test_selection_change_after_creation_stops_all_further_mutation(self):
        self.backend.after = lambda *args: setattr(self.binding, "changed", True)
        report = self.run_firefly()
        self.assertEqual(len(self.backend.calls), 2)  # about + first create
        self.assertEqual(self.row(report, "cleanup")["state"], "failed")
        self.assertTrue(self.backend.objects)

    def test_retention_is_explicit_never_passes_cleanup_or_durable_persistence(self):
        self.plan["apps"][0]["workflow"]["cleanup"] = "retain-created-for-restart-probe"
        report = self.run_firefly()
        self.assertEqual(self.row(report, "cleanup")["state"], "unproven")
        self.assertEqual(report["fixtures"][0]["lifecycle"], "retained-by-explicit-plan")
        self.assertEqual(len(self.backend.objects), 3)
        self.assertFalse(any(method == "DELETE" for method, _, _ in self.backend.calls))
        self.assertEqual(report["durablePersistence"]["state"], "unproven")

    def test_native_report_never_contains_cookie_csrf_subject_or_financial_fields(self):
        report = self.run_firefly()
        serialized = json.dumps(report)
        for forbidden in (SUBJECT, "SYNTHETIC-NATIVE", self.secret["member"]["password"],
                          "source_id", "destination_id", "account_role", "p0-browser-" + RUN, "1.25"):
            self.assertNotIn(forbidden, serialized)

    def test_no_native_second_login_or_cross_origin_app_api(self):
        self.page.url = self.plan["keycloak"]["url"] + "/realms/fixture/login"
        report = self.run_firefly()
        self.assertEqual(self.row(report, "workflow")["state"], "failed")
        self.assertFalse(self.backend.calls)
        self.assertFalse(self.browser.fills)

    def test_exact_native_workflow_plan_schema_rejects_loose_or_destructive_extensions(self):
        for driver in h.WORKFLOWS:
            base = native_plan(driver)
            self.assertTrue(h.validate_plan(base, NOW))
            for change in ({"kind": "guessed-rest-api"}, {"cleanup": "delete-all"},
                           {"cleanup": None}, {"script": "arbitrary mutation"}):
                with self.subTest(driver=driver, change=change):
                    value = copy.deepcopy(base)
                    value["apps"][0]["workflow"].update(change)
                    with self.assertRaises((h.Refused, ValueError)):
                        h.validate_plan(value, NOW)


    def test_currency_date_language_root_and_required_workflow_keys_are_strict(self):
        for driver, fields in (("firefly-iii", ({"date": "2026-02-30"}, {"date": "20261024"},
                     {"currency": "eur"}, {"currency": "EUR;DELETE"})),
                               ("huly", ({"language": "de"}, {"language": None}))):
            for change in fields:
                with self.subTest(driver=driver, change=change):
                    value = native_plan(driver)
                    value["apps"][0]["workflow"].update(change)
                    with self.assertRaises((h.Refused, ValueError)):
                        h.validate_plan(value, NOW)
            for kind in ("workflow-missing", "non-root"):
                value = native_plan(driver)
                if kind == "workflow-missing":
                    del value["apps"][0]["workflow"]["cleanup"]
                else:
                    value["apps"][0]["url"] += "existing/"
                with self.assertRaises(h.Refused):
                    h.validate_plan(value, NOW)

    def test_native_subjects_validate_through_real_private_fd_reader(self):
        with tempfile.NamedTemporaryFile() as stream:
            os.fchmod(stream.fileno(), 0o600)
            for subjects in ({"firefly-iii": SUBJECT}, {"firefly-iii": SUBJECT.upper()},
                             {"firefly-iii": "not-a-subject"}, [], {"BAD/KEY": SUBJECT}):
                self.secret["member"]["nativeSubjects"] = subjects
                stream.seek(0); stream.truncate()
                stream.write(json.dumps(self.secret).encode()); stream.flush()
                if subjects == {"firefly-iii": SUBJECT}:
                    self.assertEqual(h.credentials(None, fd=stream.fileno()), self.secret)
                else:
                    with self.assertRaises(h.Refused):
                        h.credentials(None, fd=stream.fileno())


class HulyLocator:
    """Strict stateful native UI boundary model; NOT live selector evidence."""
    def __init__(self, page, css, first=False):
        self.page, self.css, self.is_first = page, css, first
    @property
    def model(self):
        return self.page.model
    @property
    def first(self):
        return HulyLocator(self.page, self.css, True)
    def locator(self, css):
        return HulyLocator(self.page, self.css + " >> " + css)
    def count(self):
        if self.css == 'input[type="password"]:visible':
            return int(self.model.native_login)
        if 'div.listGrid a:text-is' in self.css:
            return int(self.model.task is not None and self.model.task["title"] in self.css)
        if 'button.hulyNavGroup-header span:text-is' in self.css:
            return int(self.model.project is not None and self.model.project["title"] in self.css)
        if self.css == '.ws > button':
            return 1 if self.is_first or not self.model.edit_workspace else 2
        return 1
    def wait_for(self, state):
        assert (self.count() > 0) if state == "visible" else self.count() == 0
    def hover(self):
        self.model.actions.append(("hover", self.css))
    def get_attribute(self, key):
        assert key == "href"
        root = self.model.root + "/workbench/" + self.model.workspace["url"] + "/tracker/"
        if 'div.listGrid a:text-is' in self.css:
            assert self.model.task is not None
            return root + self.model.task["id"]
        assert 'a[href*="issues"]' in self.css and self.model.project is not None
        return root + self.model.project["id"] + "/issues"
    def input_value(self):
        if self.css == '.ws .editBox input':
            return self.model.workspace["name"]
        if 'popupPanel-body input' in self.css:
            assert self.model.task is not None
            return self.model.task["title"]
        if 'project-title' in self.css:
            return self.model.project["title"]
        assert 'project-description' in self.css
        return self.model.project["description"]
    def inner_text(self):
        assert 'popupPanel-body div.textInput div.tiptap' in self.css
        return self.model.task["description"]
    def fill(self, text):
        self.model.actions.append(("fill", self.css))
        if 'popupPanel-body input' in self.css:
            self.model.task["title"] = text
        else:
            self.model.fields[self.css] = text
    def click(self, **kw):
        model, css = self.model, self.css
        model.actions.append(("click", css))
        assert not kw  # No destructive/context-menu controls in retention mode.
        if css == 'div.form-row button':
            assert model.workspace is None
            model.workspace = {"uuid": "22222222-2222-2222-2222-222222222222",
                "name": model.fields['input[name="workspace"]'], "url": "p0-synthetic"}
            self.page.url = model.root + "/workbench/p0-synthetic/tracker/"
        elif css == 'button[id$="TrackerApplication"]' or css == '#tree-projects':
            pass
        elif css == 'form[id="tracker:string:NewProject"] button[type="submit"]':
            assert model.project is None
            model.project = {"id": "synthetic-project", "title": model.fields['div[id="project-title"] input'],
                             "description": model.fields['div[id="project-description"] input']}
        elif css.endswith(' >> div[class*="tools"] button'):
            assert model.project is not None
        elif css == 'div.selectPopup button.menu-item:text-is("Edit project")':
            assert model.project is not None
        elif css == 'form[id="tracker:string:EditProject"] button[type="submit"]':
            key = 'form[id="tracker:string:EditProject"] div[id="project-description"] input'
            if key in model.fields:
                model.project["description"] = model.fields[key]
        elif css.startswith('button.hulyNavGroup-header span:text-is'):
            assert model.project is not None
        elif css == '#tracker-string-NewIssue':
            assert model.project is not None
        elif css == 'button > span:text-is("Create issue")':
            assert model.task is None
            model.task = {"id": "P0AAAA-1", "title": model.fields['form[id="tracker:string:NewIssue"] input[type="text"]'],
                          "description": model.fields['form[id="tracker:string:NewIssue"] div.tiptap']}
        elif css == '.ws > button':
            if model.edit_workspace:
                model.workspace["name"] = model.fields['.ws .editBox input']
            model.edit_workspace = not model.edit_workspace
        else:
            raise AssertionError("unmodeled native control")
        model.after(css)


class HulyModel:
    def __init__(self, plan, subject=SUBJECT):
        self.root, self.subject = h.origin(plan["apps"][0]["url"]), subject
        self.workspace = self.project = self.task = None
        self.fields, self.actions, self.requests = {}, [], []
        self.native_login, self.cookie, self.edit_workspace = False, True, False
        self.after = lambda css: None
        self.foreign = {"uuid": "33333333-3333-3333-3333-333333333333", "name": "Other workspace", "url": "other"}
    def fetch(self, url, method, max_redirects, timeout, **kw):
        assert url == self.root + "/_accounts" and method == "POST" and max_redirects == 0
        assert "Authorization" not in kw["headers"]
        body = kw["data"]
        assert body["params"] == {} and body["method"] in ("getLoginInfoByToken", "getUserWorkspaces")
        self.requests.append(body["method"])
        if body["method"] == "getLoginInfoByToken":
            return Response(200, {"result": {"account": self.subject, "token": "SYNTHETIC-NATIVE-SECRET"}})
        return Response(200, {"result": [self.foreign] + ([self.workspace] if self.workspace else [])})


class HulyPage:
    def __init__(self, model):
        self.model, self.url = model, model.root + "/"
        self.keyboard = SimpleNamespace(press=lambda key: None)
    def locator(self, css):
        return HulyLocator(self, css)
    def goto(self, url, **kw):
        self.url = url
        return Response(200)
    def reload(self, **kw):
        pass


class HulyWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.plan = native_plan("huly")
        self.plan["apps"][0]["workflow"]["cleanup"] = "retain-created-for-restart-probe"
        self.secret = secrets()
        self.secret["member"]["nativeSubjects"] = {"huly": SUBJECT}
        self.binding = FakeBinding(self.plan)
        self.runner = h.Harness(self.binding, self.secret, Browser(self.plan, self.secret))
        self.model = HulyModel(self.plan)
        self.page = HulyPage(self.model)
        self.context = SimpleNamespace(request=self.model, cookies=lambda urls: ([{
            "name": "account-metadata-Token", "value": "SYNTHETIC-NATIVE-SECRET", "secure": True, "httpOnly": True}]
            if self.model.cookie else []))
        # Authentication is the existing separately tested SSO observer. This
        # test class models native controls, never advertises installed SSO.
        authenticated = patch.object(self.runner, "authenticated")
        authenticated.start(); self.addCleanup(authenticated.stop)
    def run_huly(self):
        self.runner.huly(self.context, self.page, self.plan["apps"][0])
        return self.runner.evidence.result()
    def row(self, report, scope):
        return next(row for row in report["checks"] if row["target"] == "huly" and row["scope"] == scope)
    def test_native_ui_workspace_project_task_roundtrip_retention_model_only(self):
        before = copy.deepcopy(self.model.foreign)
        report = self.run_huly()
        for scope in ("workflow", "persistence"):
            self.assertEqual(self.row(report, scope)["state"], "passed", report)
        self.assertEqual(self.row(report, "cleanup")["state"], "unproven")
        self.assertIsNotNone(self.model.workspace)
        self.assertEqual(self.model.foreign, before)
        self.assertEqual([row["kind"] for row in report["fixtures"][0]["objects"]], ["workspace", "project", "task"])
        self.assertEqual(report["fixtures"][0]["lifecycle"], "retained-by-explicit-plan")
        self.assertFalse(report["browserScopesPassed"])
        self.assertEqual(report["durablePersistence"]["state"], "unproven")
        self.assertTrue(set(self.model.requests) == {"getLoginInfoByToken", "getUserWorkspaces"})
    def test_missing_native_huly_cookie_refuses_not_skipped_or_pat_fallback(self):
        self.model.cookie = False
        report = self.run_huly()
        self.assertEqual(self.row(report, "workflow")["state"], "unproven")
        self.assertEqual(self.row(report, "workflow")["code"], "huly-native-cookie-session-unproven")
        self.assertFalse(self.model.actions)
        self.assertFalse(self.model.requests)
    def test_duplicate_huly_cookie_not_resolved_by_filtering_unsafe_duplicates(self):
        cookie = self.context.cookies([])[0]
        self.context.cookies = lambda urls: [cookie, dict(cookie, httpOnly=False)]
        report = self.run_huly()
        self.assertEqual(self.row(report, "workflow")["state"], "unproven")
        self.assertFalse(self.model.requests)
        self.assertFalse(self.model.actions)
    def test_missing_websocket_policy_is_specific_unproven_and_closes_context(self):
        report = self.runner.run()
        self.assertEqual(self.row(report, "workflow")["code"], "huly-websocket-policy-unavailable")
        self.assertEqual(self.row(report, "workflow")["state"], "unproven")
        self.assertTrue(all(context.closed for context in self.runner.browser.contexts))
        self.assertFalse(self.runner.browser.calls)
        self.assertFalse(self.runner.browser.fills)
    def test_mismatched_huly_native_account_never_creates_workspace(self):
        self.model.subject = "another-account"
        report = self.run_huly()
        self.assertEqual(self.row(report, "workflow")["code"], "huly-native-account-mismatch")
        self.assertFalse(self.model.actions)
    def test_partial_native_fixture_is_retained_never_cascaded(self):
        def fail(css):
            if css == '#tree-projects':
                raise RuntimeError("SYNTHETIC-NATIVE-SECRET")
        self.model.after = fail
        report = self.run_huly()
        self.assertIsNotNone(self.model.workspace)
        self.assertEqual(self.row(report, "workflow")["state"], "failed")
        self.assertEqual(self.row(report, "cleanup")["state"], "unproven")
        self.assertFalse(any("Delete workspace" in css for _, css in self.model.actions))
        self.assertNotIn("SYNTHETIC-NATIVE-SECRET", json.dumps(report))
    def test_workspace_identity_change_prevents_all_destructive_cleanup(self):
        def changed(css):
            if css == 'button > span:text-is("Create issue")':
                self.model.workspace["name"] = "unrelated state"
        self.model.after = changed
        report = self.run_huly()
        self.assertEqual(self.row(report, "workflow")["state"], "failed")
        self.assertEqual(self.row(report, "cleanup")["state"], "unproven")
        self.assertFalse(any('DeleteObject' in css or 'Delete workspace' in css for _, css in self.model.actions))
    def test_delete_created_refuses_before_network_or_mutation_without_exact_native_hook(self):
        self.plan["apps"][0]["workflow"]["cleanup"] = "delete-created"
        report = self.run_huly()
        for scope in ("workflow", "cleanup"):
            self.assertEqual(self.row(report, scope)["state"], "unproven")
            self.assertEqual(self.row(report, scope)["code"], "huly-native-exact-cleanup-hook-required")
        self.assertFalse(self.model.requests)
        self.assertFalse(self.model.actions)
        self.assertIsNone(self.model.workspace)
    def test_filtered_workspace_absence_cannot_be_counted_as_deletion(self):
        report = self.run_huly()
        self.model.workspace = None  # Could be pending-deletion and merely hidden.
        self.assertEqual(self.row(report, "cleanup")["state"], "unproven")
        self.assertFalse(report["browserScopesPassed"])
    def test_huly_retained_ids_digest_only_no_native_token_or_subject(self):
        self.plan["apps"][0]["workflow"]["cleanup"] = "retain-created-for-restart-probe"
        report = self.run_huly()
        self.assertEqual(self.row(report, "cleanup")["state"], "unproven")
        self.assertEqual(report["fixtures"][0]["lifecycle"], "retained-by-explicit-plan")
        serialized = json.dumps(report)
        for forbidden in (SUBJECT, "SYNTHETIC-NATIVE", "p0-project-" + RUN, "p0-task-" + RUN, "Other workspace"):
            self.assertNotIn(forbidden, serialized)
    def test_huly_selection_revocation_prevents_ui_mutations_and_cleanup(self):
        def changed(css):
            if css == 'form[id="tracker:string:NewProject"] button[type="submit"]':
                self.binding.changed = True
        self.model.after = changed
        report = self.run_huly()
        self.assertEqual(self.row(report, "workflow")["state"], "failed")
        self.assertEqual(self.row(report, "cleanup")["state"], "unproven")
        self.assertFalse(any('Delete' in css for _, css in self.model.actions))
    def test_websocket_route_only_allows_native_same_origin_tls_endpoints(self):
        context = Context(self.runner.browser)
        context.route_web_socket = lambda pattern, handler: setattr(context, "ws_handler", handler)
        with patch.object(self.runner.browser, "new_context", return_value=context):
            self.runner.context()
        for url, expected in (("wss://huly.fixture.test/_transactor/native-session", True),
                              ("wss://huly.fixture.test/_collaborator", True),
                              ("ws://huly.fixture.test/_transactor", False),
                              ("wss://foreign.fixture.test/_transactor", False),
                              ("wss://huly.fixture.test/other", False)):
            events = []
            socket = SimpleNamespace(url=url, connect_to_server=lambda: events.append(True), close=lambda: events.append(False))
            context.ws_handler(socket)
            self.assertEqual(events, [expected])
        self.binding.changed = True
        events = []
        context.ws_handler(SimpleNamespace(url="wss://huly.fixture.test/_transactor/native-session",
            connect_to_server=lambda: events.append(True), close=lambda: events.append(False)))
        self.assertEqual(events, [False])


if __name__ == "__main__":
    unittest.main(verbosity=2)
