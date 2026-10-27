import ast
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest

import kinetic_trust_library


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_DIRECTORY = Path(kinetic_trust_library.__file__).resolve().parent
SOURCE_DIRECTORY = ROOT / "src"
FORBIDDEN_IMPORT_ROOTS = {
    "kinetic_trust_service",
    "requests",
    "httpx",
    "socket",
    "sqlite3",
    "sqlalchemy",
}


def source_boundary_violations(root: Path) -> tuple[str, ...]:
    violations: list[str] = []

    class BoundaryVisitor(ast.NodeVisitor):
        def __init__(self, relative_path: Path) -> None:
            self.relative_path = relative_path
            self.imported_names: dict[str, str] = {}

        def report(self, node: ast.AST, kind: str, name: str) -> None:
            violations.append(
                f"{self.relative_path.as_posix()}:{node.lineno}: {kind} {name}"
            )

        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".", 1)[0]
                self.imported_names[local_name] = (
                    alias.name if alias.asname else local_name
                )
                root_name = alias.name.split(".", 1)[0]
                if root_name in FORBIDDEN_IMPORT_ROOTS:
                    self.report(node, "forbidden import", alias.name)
            self.generic_visit(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            module = node.module or ""
            root_name = module.split(".", 1)[0]
            if root_name in FORBIDDEN_IMPORT_ROOTS:
                self.report(node, "forbidden import", module)
            for alias in node.names:
                local_name = alias.asname or alias.name
                self.imported_names[local_name] = f"{module}.{alias.name}"
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            if self.resolved_name(node) == "os.environ":
                self.report(node, "forbidden runtime access", "os.environ")
            self.generic_visit(node)

        def visit_Name(self, node: ast.Name) -> None:
            if self.resolved_name(node) == "os.environ":
                self.report(node, "forbidden runtime access", "os.environ")
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            name = self.resolved_name(node.func)
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "open"
                and isinstance(node.func.value, ast.Call)
                and self.resolved_name(node.func.value.func) in {"pathlib.Path", "Path"}
            ):
                name = "Path.open"
            forbidden_name = {
                "time.time": "time.time",
                "time.monotonic": "time.monotonic",
                "time.sleep": "time.sleep",
                "os.getenv": "os.getenv",
                "pathlib.Path.open": "Path.open",
                "Path.open": "Path.open",
                "open": "open",
                "importlib.metadata.entry_points": "importlib.metadata.entry_points",
            }.get(name)
            if forbidden_name is not None:
                self.report(node, "forbidden runtime access", forbidden_name)
            self.generic_visit(node)

        def resolved_name(self, node: ast.AST) -> str | None:
            if isinstance(node, ast.Name):
                return self.imported_names.get(node.id, node.id)
            if isinstance(node, ast.Attribute):
                value = self.resolved_name(node.value)
                if value is not None:
                    return f"{value}.{node.attr}"
            return None

    for source_path in sorted(root.rglob("*.py")):
        relative_path = source_path.relative_to(root)
        if relative_path == Path("adapters/cryptography.py"):
            continue
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=source_path)
        BoundaryVisitor(relative_path).visit(tree)

    return tuple(violations)


def child_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["KTP_EXPECTED_PACKAGE_DIRECTORY"] = str(PACKAGE_DIRECTORY)
    if PACKAGE_DIRECTORY.is_relative_to(SOURCE_DIRECTORY):
        environment["PYTHONPATH"] = str(SOURCE_DIRECTORY)
    else:
        environment.pop("PYTHONPATH", None)
    return environment


class DependencyPolicyTests(unittest.TestCase):
    def test_project_declares_only_routinely_tested_python_versions(self):
        with (ROOT / "pyproject.toml").open("rb") as source:
            project = tomllib.load(source)["project"]

        classifiers = set(project["classifiers"])
        self.assertEqual(project["requires-python"], ">=3.11")
        expected = {
            f"Programming Language :: Python :: 3.{minor}"
            for minor in range(11, 16)
        }
        declared_minors = {
            item
            for item in classifiers
            if item.startswith("Programming Language :: Python :: 3.")
        }
        self.assertEqual(declared_minors, expected)
        self.assertFalse(any("Implementation ::" in item for item in classifiers))

    def test_ci_uses_routine_project_checks(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

        matrix = 'python-version: ["3.11", "3.12", "3.13", "3.14", "3.15"]'
        base_job = workflow.split("\n  base:\n", 1)[1].split("\n  crypto:\n", 1)[0]
        crypto_job = workflow.split("\n  crypto:\n", 1)[1].split("\n  package:\n", 1)[0]
        package_job = workflow.split("\n  package:\n", 1)[1]
        self.assertEqual(base_job.count(matrix), 1)
        self.assertEqual(crypto_job.count(matrix), 1)
        self.assertNotIn("matrix:", package_job)
        self.assertIn('python-version: "3.11"', package_job)
        self.assertIn("python -m build", workflow)
        self.assertNotIn("check_release", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("release-report", workflow)

    def test_ci_has_fail_closed_required_gate(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("on:\n  push:\n    branches: [main]\n  pull_request:\n", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        required = workflow.split("\n  required:\n", 1)[1]
        self.assertIn("    name: required\n", required)
        self.assertIn("    if: ${{ always() }}\n", required)
        self.assertIn("    needs: [base, crypto, package]\n", required)
        self.assertIn("          BASE_RESULT: ${{ needs.base.result }}\n", required)
        self.assertIn("          CRYPTO_RESULT: ${{ needs.crypto.result }}\n", required)
        self.assertIn("          PACKAGE_RESULT: ${{ needs.package.result }}\n", required)
        self.assertIn('          test "$BASE_RESULT" = success\n', required)
        self.assertIn('          test "$CRYPTO_RESULT" = success\n', required)
        self.assertIn('          test "$PACKAGE_RESULT" = success\n', required)
        self.assertNotIn("skipped", required)
        self.assertNotIn("neutral", required)

    def test_workflow_actions_are_github_owned_and_immutable(self):
        action_reference = re.compile(r"^\s*uses:\s*([^@\s]+)@([^\s#]+)")
        workflow_root = ROOT / ".github" / "workflows"
        workflow_paths = sorted(
            {*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")}
        )

        self.assertGreaterEqual(len(workflow_paths), 3)
        found = 0
        for path in workflow_paths:
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                match = action_reference.match(line)
                if match is None:
                    continue
                found += 1
                action, revision = match.groups()
                owner = action.split("/", 1)[0]
                with self.subTest(path=path, line=line_number, action=action):
                    self.assertTrue(
                        owner in {"actions", "github"}
                        or action == "pypa/gh-action-pypi-publish"
                    )
                    self.assertRegex(revision, r"\A[0-9a-f]{40}\Z")
        self.assertGreater(found, 0)

    def test_release_workflow_is_tag_bound_and_uses_oidc(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            'on:\n  push:\n    tags:\n      - "v*"\n',
            workflow,
        )
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertNotIn("schedule:", workflow)
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertNotIn("write-all", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertIn("github.ref_name", workflow)
        self.assertIn("github.ref_type", workflow)
        self.assertIn("          fetch-depth: 0\n", workflow)
        self.assertIn(
            "git merge-base --is-ancestor HEAD refs/remotes/origin/main",
            workflow,
        )
        self.assertIn("pyproject.toml", workflow)
        self.assertIn("tomllib", workflow)
        self.assertIn('expected_tag = f"v{project[\'version\']}"', workflow)
        self.assertIn(
            'if ref_type != "tag" or ref_name != expected_tag:',
            workflow,
        )
        self.assertIn("uses: actions/upload-artifact@", workflow)
        self.assertIn("uses: actions/download-artifact@", workflow)
        self.assertIn("uses: pypa/gh-action-pypi-publish@", workflow)
        self.assertIn("\n  publish:\n", workflow)
        build_job = workflow.split("\n  build:\n", 1)[1].split(
            "\n  publish:\n", 1
        )[0]
        self.assertNotIn("id-token: write", build_job)
        publish_job = workflow.split("\n  publish:\n", 1)[1]
        self.assertIn("    needs: build\n", publish_job)
        self.assertIn(
            "    environment:\n"
            "      name: pypi\n"
            "      url: https://pypi.org/p/kinetic-trust-library\n",
            publish_job,
        )
        self.assertIn("    permissions:\n      id-token: write\n", publish_job)
        self.assertEqual(publish_job.count("id-token: write"), 1)
        self.assertIn("      packages-dir: dist/\n", publish_job)
        self.assertNotIn("password:", publish_job)
        self.assertNotIn("secrets.", publish_job)

    def test_codeql_keeps_untrusted_pull_requests_on_the_no_upload_path(self):
        workflow = (ROOT / ".github" / "workflows" / "codeql.yml").read_text(
            encoding="utf-8"
        )
        upload_mode = (
            "${{ github.event_name == 'pull_request' && "
            "(github.actor == 'dependabot[bot]' || "
            "github.event.pull_request.head.repo.fork == true) && "
            "'never' || 'always' }}"
        )
        artifact_guard = (
            "${{ always() && github.event_name == 'pull_request' && "
            "(github.actor == 'dependabot[bot]' || "
            "github.event.pull_request.head.repo.fork == true) }}"
        )

        self.assertIn('language: ["python", "actions"]', workflow)
        self.assertIn("build-mode: none", workflow)
        self.assertIn("security-events: write", workflow)
        self.assertIn(f"upload: {upload_mode}", workflow)
        self.assertIn(f"if: {artifact_guard}", workflow)
        self.assertIn("output: sarif-results", workflow)
        self.assertIn("path: ${{ steps.analyze.outputs.sarif-output }}", workflow)
        self.assertIn("if-no-files-found: error", workflow)
        self.assertNotIn("pull_request_target:", workflow)

    def test_maintained_docs_declare_the_exact_tested_python_set(self):
        paths = (
            ROOT / "README.md",
            ROOT / "CONTEXT.md",
            ROOT / "docs" / "releasing.md",
        )
        for path in paths:
            with self.subTest(path=path):
                content = path.read_text(encoding="utf-8")
                self.assertIn(
                    "CPython 3.11 through 3.15",
                    content,
                )
                self.assertNotIn("Python 3.11 and 3.12", content)
                self.assertNotIn("Python 3.11 or 3.12", content)
        self.assertIn(
            "for KTP_PYTHON_VERSION in 3.11 3.12 3.13 3.14 3.15; do",
            (ROOT / "docs" / "releasing.md").read_text(encoding="utf-8"),
        )

    def test_core_source_boundary_reports_forbidden_runtime_access(self):
        source = """\
import requests
from sqlalchemy import create_engine
import time
import os
from pathlib import Path
import importlib.metadata
from os import environ
from os import environ as process_environment

time.time()
time.monotonic()
time.sleep(0)
os.getenv("SETTING")
os.environ["SETTING"]
environ["SETTING"]
process_environment["SETTING"]
Path("state.txt").open()
open("state.txt")
importlib.metadata.entry_points()
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "forbidden.py").write_text(source, encoding="utf-8")

            self.assertEqual(
                source_boundary_violations(root),
                (
                    "forbidden.py:1: forbidden import requests",
                    "forbidden.py:2: forbidden import sqlalchemy",
                    "forbidden.py:10: forbidden runtime access time.time",
                    "forbidden.py:11: forbidden runtime access time.monotonic",
                    "forbidden.py:12: forbidden runtime access time.sleep",
                    "forbidden.py:13: forbidden runtime access os.getenv",
                    "forbidden.py:14: forbidden runtime access os.environ",
                    "forbidden.py:15: forbidden runtime access os.environ",
                    "forbidden.py:16: forbidden runtime access os.environ",
                    "forbidden.py:17: forbidden runtime access Path.open",
                    "forbidden.py:18: forbidden runtime access open",
                    "forbidden.py:19: forbidden runtime access importlib.metadata.entry_points",
                ),
            )

    def test_core_source_boundary_has_no_forbidden_runtime_access(self):
        self.assertEqual(source_boundary_violations(PACKAGE_DIRECTORY), ())

    def test_metadata_has_dependency_free_base_and_explicit_proof_extras(self):
        with (ROOT / "pyproject.toml").open("rb") as source:
            project = tomllib.load(source)["project"]

        self.assertEqual(project["name"], "kinetic-trust-library")
        self.assertEqual(project["version"], "2.1.0")
        self.assertEqual(
            project["urls"]["Specification"],
            "https://github.com/nmcitra/ktp-rfc/tree/v2.1.0",
        )
        self.assertEqual(project["dependencies"], [])
        self.assertEqual(
            project["optional-dependencies"],
            {
                "cryptography": ["cryptography>=50.0.0,<51"],
                "v3-proofs": [
                    "cryptography>=50.0.0,<51",
                    "rfc8785>=0.1.4,<0.2",
                    "jsonschema>=4.26,<5",
                ],
            },
        )

    def test_old_source_namespace_is_absent(self):
        self.assertFalse((ROOT / "src/kinetic_trust_core").exists())

    def test_base_imports_do_not_attempt_to_import_cryptography(self):
        script = r'''\
import builtins
import sys

real_import = builtins.__import__

def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "cryptography" or name.startswith("cryptography."):
        raise AssertionError(f"base import attempted {name}")
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = guarded_import
import kinetic_trust_library
import os
from pathlib import Path

expected = Path(os.environ["KTP_EXPECTED_PACKAGE_DIRECTORY"]).resolve()
actual = Path(kinetic_trust_library.__file__).resolve().parent
assert actual == expected, (actual, expected)
import kinetic_trust_library.models
import kinetic_trust_library.core
import kinetic_trust_library.protocols
import kinetic_trust_library.proofs
import kinetic_trust_library.adapters
import kinetic_trust_library.adapters.cryptography
assert not any(
    name == "cryptography" or name.startswith("cryptography.")
    for name in sys.modules
)
'''
        with tempfile.TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=temporary,
                env=child_environment(),
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_project_and_runtime_versions_match_exactly(self):
        with (ROOT / "pyproject.toml").open("rb") as source:
            project_version = tomllib.load(source)["project"]["version"]
        self.assertEqual(project_version, kinetic_trust_library.__version__)
        self.assertEqual(project_version, "2.1.0")


if __name__ == "__main__":
    unittest.main()
