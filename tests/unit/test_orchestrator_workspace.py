from __future__ import annotations

from pathlib import Path

import pytest

from kraken.orchestrator import (
    _build_dir_challenge_config,
    _inject_helper_scripts,
    _normalize_challenge_id,
    _resolve_solve_workspace,
    _safe_workspace_name,
)


def test_safe_workspace_name_sanitizes():
    assert _safe_workspace_name("Basic 01 / weird") == "Basic_01_weird_solution_artifacts"


def test_resolve_workspace_uses_env_base(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("KRAKEN_SOLVE_WORKSPACE_BASE", str(tmp_path))
    ws = Path(_resolve_solve_workspace("Basic"))
    assert ws.parent == tmp_path
    assert ws.name == "Basic_solution_artifacts"
    assert ws.exists()


def test_resolve_workspace_strict_mode_raises_when_base_unwritable(tmp_path: Path, monkeypatch):
    target = (tmp_path / "Basic_solution_artifacts").resolve()
    monkeypatch.setenv("KRAKEN_SOLVE_WORKSPACE_BASE", str(tmp_path))
    monkeypatch.delenv("KRAKEN_SOLVE_WORKSPACE_FALLBACK", raising=False)

    orig_mkdir = Path.mkdir

    def fake_mkdir(self, *args, **kwargs):
        if self.resolve() == target:
            raise PermissionError("simulated permission denied")
        return orig_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fake_mkdir)

    with pytest.raises(RuntimeError, match="Unable to create solve workspace in invocation directory"):
        _resolve_solve_workspace("Basic")


def test_resolve_workspace_fallback_mode_uses_tmp(monkeypatch):
    monkeypatch.setenv("KRAKEN_SOLVE_WORKSPACE_BASE", "/proc/definitely-not-writable")
    monkeypatch.setenv("KRAKEN_SOLVE_WORKSPACE_FALLBACK", "1")
    ws = Path(_resolve_solve_workspace("Basic"))
    assert ws.name == "Basic_solution_artifacts"
    assert ws.exists()


def test_resolve_workspace_uses_sudo_helper_when_enabled(tmp_path: Path, monkeypatch):
    target = (tmp_path / "Basic_solution_artifacts").resolve()
    monkeypatch.setenv("KRAKEN_SOLVE_WORKSPACE_BASE", str(tmp_path))
    monkeypatch.setenv("KRAKEN_SOLVE_WORKSPACE_USE_SUDO", "1")

    orig_mkdir = Path.mkdir

    def fake_mkdir(self, *args, **kwargs):
        if self.resolve() == target and not getattr(fake_mkdir, "allowed", False):
            raise PermissionError("simulated permission denied")
        return orig_mkdir(self, *args, **kwargs)

    fake_mkdir.allowed = False

    def fake_sudo(_target: Path) -> bool:
        fake_mkdir.allowed = True
        return True

    monkeypatch.setattr(Path, "mkdir", fake_mkdir)
    monkeypatch.setattr("kraken.orchestrator._attempt_sudo_prepare_workspace", fake_sudo)

    ws = Path(_resolve_solve_workspace("Basic"))
    assert ws == target
    assert ws.exists()


def test_inject_helper_scripts_copies_and_marks_executable(tmp_path: Path):
    injected = _inject_helper_scripts(str(tmp_path))
    assert injected

    for script in injected:
        script_path = Path(script)
        assert script_path.exists()
        assert script_path.parent == tmp_path
        assert script_path.suffix == ".py"
        assert script_path.stat().st_mode & 0o111


def test_normalize_challenge_id_prefers_non_placeholder():
    cfg = {"challenge_id": "Birds", "path": "/tmp/chal"}
    out = _normalize_challenge_id(cfg, "/tmp/Basic.json")
    assert out["challenge_id"] == "Birds"


def test_normalize_challenge_id_uses_json_stem_for_placeholder():
    cfg = {"challenge_id": "Basic", "path": "/tmp/birds"}
    out = _normalize_challenge_id(cfg, "/tmp/Birds.json")
    assert out["challenge_id"] == "Birds"


def test_normalize_challenge_id_falls_back_to_binary_stem_when_no_json_path():
    cfg = {"challenge_id": "unknown", "path": "/home/VERE/week2/Birds/birds"}
    out = _normalize_challenge_id(cfg, None)
    assert out["challenge_id"] == "birds"


def test_build_dir_challenge_config_sets_path_key(tmp_path: Path):
    # Regression: `kraken solve <directory>` once built a config with only
    # "challenge_path", but solve() reads challenge_config["path"] -- crashing
    # the documented quickstart with KeyError: 'path'.
    (tmp_path / "description.txt").write_text("a rev challenge")
    cfg = _build_dir_challenge_config(tmp_path, "rev")
    assert cfg["path"] == str(tmp_path)
    assert cfg["challenge_path"] == str(tmp_path)
    assert cfg["challenge_id"] == tmp_path.name
    assert cfg["category"] == "rev"
    assert "a rev challenge" in cfg["description"]


def test_build_dir_challenge_config_defaults_category_and_empty_desc(tmp_path: Path):
    cfg = _build_dir_challenge_config(tmp_path)
    assert cfg["path"] == str(tmp_path)
    assert cfg["category"] == "rev"
    assert cfg["description"] == ""
