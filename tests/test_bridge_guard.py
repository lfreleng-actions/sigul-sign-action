# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Effective bridge regressions without Docker, credentials, DNS, or a bridge.

The container scripts are real subprocesses. A fixture ClientConfiguration
reads a system INI and HOME/.sigul/client.conf in order; the fake Sigul CLI
uses that same loader, records an attempted signing connection, and fails.
This tests the configuration boundary without importing a not-yet-added helper.
"""

from __future__ import annotations

import getpass
import importlib
import io
import json
import os
import subprocess
import sys
import textwrap
import unittest
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from functools import cached_property
from pathlib import Path
from typing import cast
from unittest import mock

from action_common import ActionError, InputError
from action_inputs import build_plan
from client_container import ContainerRun, PulledImage
from prepare_credentials import PreparedCredentials
from signing import sign_data, sign_git_tag
from sigul_action import command_sign, main

from tests.helpers import (
    GIT_FIXTURE_ENV,
    PINS_DIR,
    REPOSITORY,
    base_env,
    make_repository,
    scratch,
)

CONTAINER_SCRIPTS = REPOSITORY / "scripts" / "container"
if str(CONTAINER_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(CONTAINER_SCRIPTS))

# The container-only Sigul SDK is not installed for host-side type checking.
load_configuration = cast(
    Callable[[object, object], object],
    importlib.import_module("client_configuration").load_configuration,
)

BRIDGE = "sigul-bridge.test"
EXPECTED = BRIDGE + ":44334"
OTHER_BRIDGE = "private-unapproved-bridge.invalid"

FIXTURE_UTILS = """
import json
import os

class ConfigurationError(Exception):
    pass

class NSSInitError(Exception):
    pass

def record(event, **values):
    values.update(event=event, actor=os.environ.get('FIXTURE_ACTOR', 'preflight'))
    with open(os.environ['FIXTURE_EVENTS'], 'a') as stream:
        stream.write(json.dumps(values) + '\\n')

def nss_init(config):
    record('nss')
"""

FIXTURE_CLIENT = """
import os
import socket
try:
    from configparser import Error, RawConfigParser
except ImportError:
    from ConfigParser import Error, RawConfigParser
import utils

utils.record('client-import')

def resolve(host, port, *args):
    utils.record('dns', host=host, port=port)
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.10', port))]

# probe imports socket before loading client; patch that shared module so
# no test hostname ever reaches the host resolver.
socket.getaddrinfo = resolve

def refuse_connection(*args, **kwargs):
    raise AssertionError('the bridge fixture forbids real network connections')

socket.socket.connect = refuse_connection
socket.socket.connect_ex = refuse_connection

class ClientConfiguration(object):
    def __init__(self, user_path):
        utils.record('load-config', user_path=user_path)
        parser = RawConfigParser({'bridge-port': '44334'})
        try:
            files = parser.read([
                os.environ['FIXTURE_SYSTEM_CONF'], os.path.expanduser(user_path)
            ])
            self.bridge_hostname = parser.get('client', 'bridge-hostname')
            self.bridge_port = parser.getint('client', 'bridge-port')
            self.server_hostname = parser.get('client', 'server-hostname')
            self.user_name = parser.get('client', 'user-name')
            self.client_cert_nickname = parser.get('client', 'client-cert-nickname')
            self.nss_dir = parser.get('nss', 'nss-dir')
            self.nss_password = parser.get('nss', 'nss-password')
        except (Error, ValueError) as error:
            raise utils.ConfigurationError(str(error))
        utils.record('configuration', files=files,
                     host=self.bridge_hostname, port=self.bridge_port)
"""

FIXTURE_NSS = """
class Certificate(object):
    subject = 'CN=fixture'

    def check_valid_times(self):
        return 0

def find_cert_from_nickname(nickname):
    return Certificate()

def find_key_by_any_cert(cert):
    return object()
"""

FIXTURE_SIGUL = """
import os
import sys

if sys.argv[1:] == ['--version']:
    print('fixture-sigul')
    sys.exit(0)
if len(sys.argv) < 3 or sys.argv[2] not in ('sign-data', 'sign-git-tag'):
    sys.exit(99)
os.environ['FIXTURE_ACTOR'] = 'client'
sys.path.insert(0, os.environ['SIGULPATH'])
import utils
utils.record('signing-command', operation=sys.argv[2])
if not os.environ.get('FIXTURE_BESPOKE_CLI'):
    import client
    try:
        client.ClientConfiguration('~/.sigul/client.conf')
    except utils.ConfigurationError:
        sys.exit(24)
utils.record('connect', operation=sys.argv[2])
sys.exit(23)
"""


class BridgeFixture:
    """Materialized fixture configuration, an annotated tag, and a fake client."""

    def __init__(self, case: unittest.TestCase) -> None:
        self.case: unittest.TestCase = case
        self.root: Path = scratch(case)
        self.workspace: Path = make_repository(self.root / "workspace", tag="v1")
        self.home: Path = self.root / "pki"
        (self.home / ".sigul").mkdir(parents=True)
        self.system: Path = self.root / "system-client.conf"
        self.user: Path = self.home / ".sigul" / "client.conf"
        self.modules: Path = self.root / "modules"
        (self.modules / "nss").mkdir(parents=True)
        for name, source in (
            ("utils.py", FIXTURE_UTILS),
            ("client.py", FIXTURE_CLIENT),
            ("nss/__init__.py", ""),
            ("nss/nss.py", FIXTURE_NSS),
        ):
            _ = (self.modules / name).write_text(textwrap.dedent(source))
        self.bin: Path = self.root / "bin"
        self.bin.mkdir()
        executable = self.bin / "sigul"
        _ = executable.write_text(f"#!{sys.executable} -S\n" + FIXTURE_SIGUL)
        executable.chmod(0o755)
        self.log: Path = self.root / "events.jsonl"
        self.source: Path = self.workspace / "a.txt"
        _ = self.source.write_text("synthetic payload\n")
        self.manifest: Path = self.root / "manifest"
        _ = self.manifest.write_bytes(
            os.fsencode(self.source)
            + b"\0"
            + os.fsencode(str(self.source) + ".asc")
            + b"\0"
        )
        self.password: Path = self.root / "password"
        _ = self.password.write_bytes(b"synthetic-passphrase\0\n")
        self.configure()

    def configure(
        self,
        host: str = BRIDGE,
        port: str = "44334",
        user_host: str | None = None,
        user_port: str | None = None,
    ) -> None:
        """Write two INIs, allowing either layer to supply the bridge endpoint."""
        _ = self.system.write_text(
            "[client]\n"
            + f"bridge-hostname: {host}\nbridge-port: {port}\n"
            + "server-hostname: private-server.invalid\n"
            + "user-name: private-client-user\n"
            + "client-cert-nickname: private-certificate-name\n"
            + "[nss]\nnss-dir: /private-nss-database\n"
            + "nss-password: private-system-password\n"
        )
        override = "[nss]\nnss-password: private-bundle-password\n"
        if user_host is not None or user_port is not None:
            override += "[client]\n"
        if user_host is not None:
            override += f"bridge-hostname: {user_host}\n"
        if user_port is not None:
            override += f"bridge-port: {user_port}\n"
        _ = self.user.write_text(override)

    def disable_client_module(self) -> None:
        """Model a working bespoke CLI without importable Sigul Python modules."""
        _ = (self.modules / "client.py").write_text(
            "import utils\nutils.record('client-import')\nraise ImportError('fixture unavailable')\n"
        )

    def events(self, event: str) -> list[dict[str, object]]:
        """Return one kind of event recorded by the fixture, not production code."""
        records = [
            cast(dict[str, object], json.loads(line))
            for line in self.log.read_text().splitlines()
        ]
        return [record for record in records if record["event"] == event]

    def run(
        self,
        operation: str,
        expected: str | None = EXPECTED,
        dry_run: bool = False,
        **extra_env: str,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a real container script with no inherited job environment."""
        _ = self.log.write_text("")
        env = {
            **GIT_FIXTURE_ENV,
            "PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin",
            "HOME": str(self.home),
            "SIGULPATH": str(self.modules),
            "FIXTURE_SYSTEM_CONF": str(self.system),
            "FIXTURE_EVENTS": str(self.log),
            "MODE": operation,
            "MANIFEST": str(self.manifest),
            "GIT_TAG": "v1",
            "SIGUL_KEY": "fixture-key",
            "SIGUL_PASSWORD": str(self.password),
            "MAX_RETRIES": "1",
            "RETRY_DELAY": "0",
            "ATTEMPT_TIMEOUT": "5",
            **extra_env,
        }
        if expected is not None:
            env["EXPECTED_BRIDGE"] = expected
        script = "probe.py" if dry_run else operation.replace("-", "_") + ".py"
        done = subprocess.run(
            [sys.executable, "-B", "-E", "-S", str(CONTAINER_SCRIPTS / script)],
            cwd=self.workspace,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        # Harness failures must not be swallowed by an expectedFailure marker.
        case = self.case
        case.addCleanup(case.assertNotIn, "Traceback", done.stdout + done.stderr)
        case.addCleanup(case.assertNotIn, done.returncode, (99, 126, 127))
        return done


class EffectiveBridgeTests(unittest.TestCase):
    def assert_loaded_layers(self, fixture: BridgeFixture) -> None:
        """Prove the fake client's actual parser read both files in order."""
        configurations = fixture.events("configuration")
        self.assertTrue(configurations)
        paths = [str(path) for path in (fixture.system, fixture.user) if path.is_file()]
        for config in configurations:
            self.assertEqual(config["files"], paths)

    def assert_refused(
        self, operation: str, dry_run: bool = False, **configuration: str
    ) -> None:
        """An effective endpoint mismatch must stop before the client or NSS/DNS."""
        fixture = BridgeFixture(self)
        fixture.configure(**configuration)
        done = fixture.run(operation, dry_run=dry_run)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertEqual(
            fixture.events("signing-command"), [], "Sigul was invoked to sign"
        )
        self.assertEqual(fixture.events("connect"), [])
        self.assertEqual(fixture.events("nss"), [])
        self.assertEqual(fixture.events("dns"), [])
        self.assert_loaded_layers(fixture)
        self.assertIn("expected-bridge", done.stderr)
        self.assert_configuration_not_disclosed(done)

    def assert_configuration_not_disclosed(
        self, done: subprocess.CompletedProcess[str]
    ) -> None:
        for value in (
            OTHER_BRIDGE,
            "44335",
            "private-server.invalid",
            "private-client-user",
            "private-certificate-name",
            "/private-nss-database",
            "private-system-password",
            "private-bundle-password",
        ):
            self.assertNotIn(value, done.stdout + done.stderr)

    def test_data_refuses_a_mismatching_system_bridge(self) -> None:
        self.assert_refused("sign-data", host=OTHER_BRIDGE)

    def test_tag_refuses_a_mismatching_system_bridge(self) -> None:
        self.assert_refused("sign-git-tag", host=OTHER_BRIDGE)

    def test_data_refuses_a_bundle_override_of_an_approved_bridge(self) -> None:
        self.assert_refused("sign-data", user_host=OTHER_BRIDGE)

    def test_tag_refuses_a_bundle_override_of_an_approved_bridge(self) -> None:
        self.assert_refused("sign-git-tag", user_host=OTHER_BRIDGE)

    def test_data_compares_the_effective_port_too(self) -> None:
        self.assert_refused("sign-data", user_port="44335")

    def test_tag_compares_the_effective_port_too(self) -> None:
        self.assert_refused("sign-git-tag", user_port="44335")

    def test_data_does_not_strip_multiple_trailing_dots(self) -> None:
        self.assert_refused("sign-data", user_host=BRIDGE + "..")

    def test_tag_does_not_strip_multiple_trailing_dots(self) -> None:
        self.assert_refused("sign-git-tag", user_host=BRIDGE + "..")

    def test_data_probe_refuses_a_system_mismatch_before_nss_or_dns(self) -> None:
        self.assert_refused("sign-data", dry_run=True, host=OTHER_BRIDGE)

    def test_tag_probe_refuses_a_system_mismatch_before_nss_or_dns(self) -> None:
        self.assert_refused("sign-git-tag", dry_run=True, host=OTHER_BRIDGE)

    def test_data_probe_checks_the_bundle_override(self) -> None:
        self.assert_refused("sign-data", dry_run=True, user_host=OTHER_BRIDGE)

    def test_tag_probe_checks_the_bundle_override(self) -> None:
        self.assert_refused("sign-git-tag", dry_run=True, user_host=OTHER_BRIDGE)

    def test_data_probe_compares_the_effective_port_too(self) -> None:
        self.assert_refused("sign-data", dry_run=True, user_port="44335")

    def test_tag_probe_compares_the_effective_port_too(self) -> None:
        self.assert_refused("sign-git-tag", dry_run=True, user_port="44335")

    def assert_proceeds(
        self, fixture: BridgeFixture, expected: str | None = EXPECTED
    ) -> None:
        """The fake signing failure is intentional; a dry probe must succeed."""
        for operation in ("sign-data", "sign-git-tag"):
            for dry_run in (False, True):
                with self.subTest(
                    operation=operation, dry_run=dry_run, expected=expected
                ):
                    done = fixture.run(operation, expected, dry_run)
                    self.assertEqual(
                        done.returncode, 0 if dry_run else 1, done.stdout + done.stderr
                    )
                    self.assertEqual(
                        len(fixture.events("connect")), 0 if dry_run else 1
                    )
                    if dry_run:
                        self.assertEqual(len(fixture.events("nss")), 1)
                        self.assertEqual(len(fixture.events("dns")), 1)
                    self.assert_loaded_layers(fixture)
                    if not expected and not dry_run:
                        self.assertEqual(
                            [
                                event["actor"]
                                for event in fixture.events("client-import")
                            ],
                            ["client"],
                            "An opt-out must not introduce a configuration preflight",
                        )

    def test_matching_endpoint_preserves_signing_and_dry_run_behavior(self) -> None:
        self.assert_proceeds(BridgeFixture(self))

    def test_absent_bundle_user_configuration_is_allowed(self) -> None:
        fixture = BridgeFixture(self)
        fixture.user.unlink()
        self.assert_proceeds(fixture)

    def test_default_client_port_is_used_when_neither_config_sets_it(self) -> None:
        fixture = BridgeFixture(self)
        _ = fixture.system.write_text(
            fixture.system.read_text().replace("bridge-port: 44334\n", "")
        )
        self.assert_proceeds(fixture)
        self.assertEqual(fixture.events("configuration")[-1]["port"], 44334)

    def test_bundle_override_can_correct_a_bad_system_endpoint(self) -> None:
        fixture = BridgeFixture(self)
        fixture.configure(
            host=OTHER_BRIDGE, port="44335", user_host=BRIDGE, user_port="44334"
        )
        self.assert_proceeds(fixture)
        self.assertEqual(fixture.events("configuration")[-1]["host"], BRIDGE)
        self.assertEqual(fixture.events("configuration")[-1]["port"], 44334)

    def test_runtime_hostname_comparison_ignores_case_and_one_trailing_dot(
        self,
    ) -> None:
        fixture = BridgeFixture(self)
        for host in (BRIDGE.upper(), BRIDGE + ".", BRIDGE.upper() + "."):
            with self.subTest(host=host):
                fixture.configure(user_host=host)
                self.assert_proceeds(fixture)

    def test_omitted_and_empty_expectations_preserve_existing_endpoints(self) -> None:
        fixture = BridgeFixture(self)
        fixture.configure(user_host=OTHER_BRIDGE, user_port="44335")
        for expected in (None, ""):
            self.assert_proceeds(fixture, expected)

    def test_opt_out_does_not_import_sigul_modules_in_bespoke_signers(self) -> None:
        fixture = BridgeFixture(self)
        fixture.disable_client_module()
        for operation in ("sign-data", "sign-git-tag"):
            for expected in (None, ""):
                with self.subTest(operation=operation, expected=expected):
                    done = fixture.run(operation, expected, FIXTURE_BESPOKE_CLI="1")
                    self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                    self.assertEqual(len(fixture.events("connect")), 1)
                    self.assertEqual(fixture.events("client-import"), [])
                    self.assertEqual(fixture.events("load-config"), [])

    def assert_missing_modules_refused(self, operation: str) -> None:
        fixture = BridgeFixture(self)
        fixture.disable_client_module()
        done = fixture.run(operation, FIXTURE_BESPOKE_CLI="1")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertEqual(fixture.events("signing-command"), [])
        self.assertEqual(fixture.events("connect"), [])
        self.assertTrue(fixture.events("client-import"))

    def test_data_opt_in_refuses_unavailable_sigul_modules(self) -> None:
        self.assert_missing_modules_refused("sign-data")

    def test_tag_opt_in_refuses_unavailable_sigul_modules(self) -> None:
        self.assert_missing_modules_refused("sign-git-tag")

    def assert_loader_failure_refused(self, operation: str) -> None:
        fixture = BridgeFixture(self)
        fixture.configure(user_port="private-invalid-port")
        done = fixture.run(operation)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertEqual(fixture.events("signing-command"), [])
        self.assertEqual(fixture.events("connect"), [])
        self.assertEqual(len(fixture.events("load-config")), 1)
        self.assertNotIn("private-invalid-port", done.stdout + done.stderr)
        self.assert_configuration_not_disclosed(done)

    def test_data_fails_closed_when_client_configuration_rejects_the_bundle(
        self,
    ) -> None:
        self.assert_loader_failure_refused("sign-data")

    def test_tag_fails_closed_when_client_configuration_rejects_the_bundle(
        self,
    ) -> None:
        self.assert_loader_failure_refused("sign-git-tag")


class ConfigurationLoaderTests(unittest.TestCase):
    def test_successful_loading_restores_the_prompt_handler(self) -> None:
        config = object()
        with mock.patch("getpass.getpass") as original:

            def construct(path: str) -> object:
                self.assertEqual(path, "~/.sigul/client.conf")
                self.assertIsNot(getpass.getpass, original)
                return config

            client = mock.Mock(ClientConfiguration=construct)
            utils = mock.Mock(ConfigurationError=ValueError)
            self.assertIs(load_configuration(client, utils), config)
            self.assertIs(getpass.getpass, original)
            original.assert_not_called()

    def test_loader_errors_restore_the_prompt_handler_without_disclosing_values(
        self,
    ) -> None:
        for error in (
            ValueError("private-config-value"),
            RuntimeError("private-config-value"),
        ):
            with self.subTest(error=type(error).__name__):
                stderr = io.StringIO()
                client = mock.Mock(ClientConfiguration=mock.Mock(side_effect=error))
                utils = mock.Mock(ConfigurationError=ValueError)
                with mock.patch("getpass.getpass") as original, redirect_stderr(stderr):
                    with self.assertRaises(SystemExit):
                        _ = load_configuration(client, utils)
                    self.assertIs(getpass.getpass, original)
                    original.assert_not_called()
                self.assertNotIn("private-config-value", stderr.getvalue())

    def test_refused_prompts_also_restore_the_original_handler(self) -> None:
        def construct(_path: str) -> str:
            return getpass.getpass("private-prompt-text")

        stderr = io.StringIO()
        client = mock.Mock(ClientConfiguration=construct)
        utils = mock.Mock(ConfigurationError=ValueError)
        with mock.patch("getpass.getpass") as original, redirect_stderr(stderr):
            with self.assertRaises(SystemExit):
                _ = load_configuration(client, utils)
            self.assertIs(getpass.getpass, original)
            original.assert_not_called()
        self.assertIn("nss-password", stderr.getvalue())
        self.assertNotIn("private-prompt-text", stderr.getvalue())


class ExpectedBridgeInputTests(unittest.TestCase):
    @cached_property
    def workspace(self) -> Path:
        workspace = scratch(self)
        _ = (workspace / "a.txt").write_text("synthetic payload\n")
        return workspace

    @property
    def env(self) -> dict[str, str]:
        return base_env(self.workspace, CONTAINER="modern")

    def test_plan_defaults_to_an_empty_expectation(self) -> None:
        for overrides in ({}, {"EXPECTED_BRIDGE": ""}):
            with self.subTest(overrides=overrides):
                plan = build_plan({**self.env, **overrides}, PINS_DIR)
                self.assertEqual(plan.expected_bridge, "")

    def test_plan_normalizes_the_expected_endpoint(self) -> None:
        for raw, normalized in (
            ("Sigul-Bridge.Test.:044334", EXPECTED),
            ("a:1", "a:1"),
            ("bridge.test:65535", "bridge.test:65535"),
            ("a" * 63 + ".test:44334", "a" * 63 + ".test:44334"),
        ):
            with self.subTest(raw=raw):
                plan = build_plan({**self.env, "EXPECTED_BRIDGE": raw}, PINS_DIR)
                self.assertEqual(plan.expected_bridge, normalized)

    def test_malformed_expectations_are_input_errors(self) -> None:
        for raw in (
            "bridge.test",
            "bridge.test:",
            ":44334",
            "https://bridge.test:44334",
            "user@bridge.test:44334",
            "bridge.test:44334/path",
            "bridge.test:44334:extra",
            "bridge.test:0",
            "bridge.test:65536",
            "bridge.test:-1",
            "bridge.test:+44334",
            "bridge.test:1.5",
            "bridge.test:port",
            "bridge.test:４４３３４",
            "bad_host.test:44334",
            "-bridge.test:44334",
            "bridge-.test:44334",
            "bridge..test:44334",
            "bridge.test..:44334",
            "one.test two.test:44334",
            "bridge.test\nother.test:44334",
            "bridge.test:44334\nother.test:44334",
            "[2001:db8::1]:44334",
            "a" * 64 + ".test:44334",
            ".".join(["a" * 63] * 4) + ":44334",
        ):
            with (
                self.subTest(raw=raw),
                self.assertRaisesRegex(InputError, "expected-bridge"),
            ):
                _ = build_plan({**self.env, "EXPECTED_BRIDGE": raw}, PINS_DIR)

    def test_expectation_does_not_change_hosts_override_semantics(self) -> None:
        for container, mode, names in (
            ("modern", "false", "not a hostname or endpoint"),
            ("modern", "auto", "hosts-only.test"),
            ("modern", "true", "Hosts-Only.Test. second.test"),
            ("legacy", "auto", "hosts-only.test second.test"),
        ):
            with self.subTest(container=container, mode=mode):
                env = {
                    **self.env,
                    "CONTAINER": container,
                    "HOSTS_ENTRY": mode,
                    "SIGUL_URI": names,
                    "SIGUL_IP": "192.0.2.22",
                }
                before = build_plan(env, PINS_DIR)
                after = build_plan({**env, "EXPECTED_BRIDGE": EXPECTED}, PINS_DIR)
                self.assertEqual(after.hosts, before.hosts)
                self.assertEqual(after.messages, before.messages)

    def test_validation_reports_a_malformed_expectation_as_rejected(self) -> None:
        output = self.workspace / "validation-output"
        env = {
            **self.env,
            "EXPECTED_BRIDGE": "bridge.test:0",
            "GITHUB_OUTPUT": str(output),
        }
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sigul_action.check_runtime"),
            redirect_stdout(io.StringIO()),
        ):
            status = main(["validate"])
        self.assertEqual(status, 1)
        self.assertEqual(output.read_text(), "validation_status=rejected\n")

    def test_handoff_rejects_bad_structure_before_materializing_credentials(
        self,
    ) -> None:
        values = {
            "SIGUL_CONF": "fixture config",
            "SIGUL_PASS": "fixture pass",
            "SIGUL_PKI": "fixture bundle",
            "GH_KEY": "",
        }
        with (
            mock.patch.dict(
                os.environ, {**self.env, "EXPECTED_BRIDGE": "bridge.test:0"}, clear=True
            ),
            mock.patch("sigul_action.check_runtime"),
            mock.patch("sigul_action.read_handoff", return_value=values),
            mock.patch("sigul_action.sign") as materialize,
            redirect_stdout(io.StringIO()),
        ):
            status = main(["sign-handoff", "0"])
        materialize.assert_not_called()
        self.assertEqual(status, 1)

    def test_valid_structure_is_not_compared_to_raw_system_config_on_the_runner(
        self,
    ) -> None:
        # The bundle may correct this base endpoint, and has not been decrypted.
        values = {
            "SIGUL_CONF": f"[client]\nbridge-hostname: {OTHER_BRIDGE}\n",
            "SIGUL_PASS": "fixture pass",
            "SIGUL_PKI": "fixture bundle",
            "GH_KEY": "",
        }
        with (
            mock.patch.dict(
                os.environ, {**self.env, "EXPECTED_BRIDGE": EXPECTED}, clear=True
            ),
            mock.patch("sigul_action.check_runtime"),
            mock.patch("sigul_action.read_handoff", return_value=values),
            mock.patch("sigul_action.sign") as materialize,
        ):
            self.assertEqual(main(["sign-handoff", "0"]), 0)
        materialize.assert_called_once()


class ExpectedBridgeWiringTests(unittest.TestCase):
    def test_signing_reexec_keeps_the_expected_bridge(self) -> None:
        captured: dict[str, str] = {}

        def exec_boundary(_path: str, _argv: list[str], env: dict[str, str]) -> None:
            captured.update(env)
            raise RuntimeError("fixture stopped reexec")

        with (
            mock.patch.dict(
                os.environ,
                {"EXPECTED_BRIDGE": EXPECTED, "SIGUL_CONF": "synthetic secret"},
                clear=True,
            ),
            mock.patch("sigul_action.write_handoff", return_value=0),
            mock.patch("sigul_action.os.execve", side_effect=exec_boundary),
            self.assertRaisesRegex(RuntimeError, "fixture stopped reexec"),
        ):
            command_sign()
        self.assertEqual(captured.get("EXPECTED_BRIDGE"), EXPECTED)
        self.assertNotIn("SIGUL_CONF", captured)

    def assert_container_expectation(self, expected: str, normalized: str) -> None:
        """Exercise both runner signing entry points, stopping at Docker launch."""
        for operation in ("sign-data", "sign-git-tag"):
            for dry_run in (False, True):
                with self.subTest(
                    operation=operation, dry_run=dry_run, expected=expected
                ):
                    fixture = BridgeFixture(self)
                    plan = build_plan(
                        base_env(
                            fixture.workspace,
                            CONTAINER="modern",
                            SIGN_TYPE=operation,
                            SIGN_OBJECT="v1"
                            if operation == "sign-git-tag"
                            else "a.txt",
                            PUSH_TAG="false",
                            DRY_RUN=str(dry_run).lower(),
                            EXPECTED_BRIDGE=expected,
                        ),
                        PINS_DIR,
                    )
                    creds = fixture.root / "creds"
                    creds.mkdir()
                    prepared = PreparedCredentials(
                        fixture.system, "/sigul-creds/pki", "/nss", True
                    )
                    pulled = PulledImage(
                        "fixture:1", "fixture:1", "root", "linux/amd64"
                    )
                    run = ContainerRun(
                        plan, pulled, prepared, creds, "bridge-fixture", "1000:1000"
                    )
                    with (
                        mock.patch.dict(
                            os.environ,
                            {
                                "GITHUB_SERVER_URL": fixture.root.as_uri(),
                                "GITHUB_REPOSITORY": "workspace",
                                "EXPECTED_BRIDGE": "ambient.invalid:1",
                            },
                            clear=True,
                        ),
                        mock.patch("signing.run_container", return_value=1) as start,
                        redirect_stdout(io.StringIO()),
                        self.assertRaises(ActionError),
                    ):
                        if operation == "sign-data":
                            sign_data(run)
                        else:
                            sign_git_tag(run, fixture.root / "work", "")
                    start.assert_called_once()
                    argv = cast(list[str], start.call_args.args[0])
                    env = dict(
                        argv[index + 1].split("=", 1)
                        for index, arg in enumerate(argv)
                        if arg == "--env"
                    )
                    self.assertEqual(env.get("EXPECTED_BRIDGE"), normalized)
                    script = (
                        "probe.py" if dry_run else operation.replace("-", "_") + ".py"
                    )
                    self.assertEqual(argv[-1], "/sigul-scripts/" + script)
                    if dry_run:
                        self.assertEqual(env.get("MODE"), operation)

    def test_both_modes_and_dry_runs_receive_the_planned_endpoint(self) -> None:
        self.assert_container_expectation("Sigul-Bridge.Test.:044334", EXPECTED)

    def test_empty_plan_explicitly_disables_an_image_or_ambient_expectation(
        self,
    ) -> None:
        self.assert_container_expectation("", "")


if __name__ == "__main__":
    _ = unittest.main()
