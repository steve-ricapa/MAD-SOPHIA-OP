"""Check real Git pathspec behavior without starting services or collectors."""

from pathlib import Path
import re
import shlex
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "validate_service_once.sh"


def source_pathspecs():
    text = SCRIPT.read_text(encoding="utf-8")
    array = re.search(r"SOURCE_PATHS=\(\n(.*?)\n\)", text, re.DOTALL)
    assert array is not None
    paths = shlex.split(array.group(1), comments=True)
    # Both live gates must use exactly the source pathspec array tested below.
    assert 'diff --quiet -- "${SOURCE_PATHS[@]}"' in text
    assert 'diff --cached --quiet -- "${SOURCE_PATHS[@]}"' in text
    return paths


def git(repo, *args):
    return subprocess.run(
        ["git", "-c", "core.filemode=false", *args],
        cwd=repo, capture_output=True, text=True, check=True,
    )


SOURCE_FILES = (
    "collector.py", "nested/client.py", "scripts/run_hourly.sh",
    "scripts/mad-6x.service", "scripts/mad-6x.timer", ".env.example",
    "nested/.env.example", "requirements.txt", "nested/requirements-dev.txt",
    "Dockerfile", "nested/Dockerfile.test", "pyproject.toml", "setup.cfg",
    "config/collector.ini", "config/service.conf", "config/source.yaml",
    ".gitignore", ".dockerignore", "wazuh_integration/config_profiles/standard.env",
)
OPERATIONAL_FILES = (
    "runtime/last_envelope.json", "runtime/spool.db", "runtime/spool.db-wal",
    "runtime/spool.db-shm", "uptimekuma_integration/state.json",
    "uptimekuma_integration/raw_monitors_snapshot.json",
    "insightVM_integration/config/queue/payload.json",
    "openVAS_integration/__pycache__/services.cpython-313.pyc",
)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "--quiet", "--initial-branch=main")
    for name in SOURCE_FILES + OPERATIONAL_FILES:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("baseline\n", encoding="utf-8")
    git(tmp_path, "add", ".")
    hooks = tmp_path / ".git" / "empty-hooks"
    hooks.mkdir()
    git(tmp_path, "-c", "user.name=Recovery Test", "-c", "user.email=recovery@example.invalid",
        "-c", "commit.gpgsign=false", "-c", f"core.hooksPath={hooks}",
        "commit", "--quiet", "-m", "Test fixture")
    return tmp_path


def source_is_clean(repo):
    paths = source_pathspecs()
    clean = True
    for extra in ([], ["--cached"]):
        result = subprocess.run(
            ["git", "-c", "core.filemode=false", "diff", *extra, "--quiet", "--", *paths],
            cwd=repo, capture_output=True, text=True,
        )
        assert result.returncode in (0, 1), result.stderr
        clean = clean and result.returncode == 0
    return clean


@pytest.mark.parametrize("staged", [False, True])
def test_operational_data_changes_do_not_block_source_integrity(repo, staged):
    for name in OPERATIONAL_FILES:
        (repo / name).write_text("cycle output changed\n", encoding="utf-8")
    if staged:
        git(repo, "add", "--", *OPERATIONAL_FILES)

    assert source_is_clean(repo)


@pytest.mark.parametrize("name", SOURCE_FILES)
@pytest.mark.parametrize("staged", [False, True])
def test_source_and_configuration_changes_block_validation(repo, name, staged):
    (repo / name).write_text("source changed\n", encoding="utf-8")
    if staged:
        git(repo, "add", "--", name)

    assert not source_is_clean(repo)


@pytest.mark.parametrize("staged", [False, True])
def test_deleted_source_file_blocks_validation(repo, staged):
    (repo / "collector.py").unlink()
    if staged:
        git(repo, "add", "-u", "--", "collector.py")

    assert not source_is_clean(repo)


def test_staged_new_source_file_blocks_validation(repo):
    target = repo / "nested" / "new_collector.py"
    target.write_text("new code\n", encoding="utf-8")
    git(repo, "add", "--", "nested/new_collector.py")

    assert not source_is_clean(repo)
