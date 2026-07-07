# coding=utf-8
"""End-to-end CLI tests: precedence, permissions, atomic writes, error paths."""

import os
import stat
import subprocess
import sys
import shutil

import pytest

from mobilepasser import mobilepasser as cli


EXAMPLE_KEY = "QVKYC-FM6KO-SY6F7-TR22W"


# --- helpers ----------------------------------------------------------------


def _write_config(path, activation_key=EXAMPLE_KEY, index=0, policy="",
                  otp_length=6, auto_update=False, mode=0o600):
    with open(path, "w") as f:
        f.write(
            "[MobilePASS]\n"
            "activation_key = {k}\n"
            "index = {i}\n"
            "policy = {p}\n"
            "otp_length = {l}\n"
            "auto_update_index = {a}\n".format(
                k=activation_key, i=index, p=policy, l=otp_length, a=auto_update
            )
        )
    os.chmod(path, mode)


def _run_cli(*args, cwd=None):
    """Run the CLI via ``python -m`` and return CompletedProcess."""
    return subprocess.run(
        [sys.executable, "-m", "mobilepasser.mobilepasser", *args],
        capture_output=True, text=True, cwd=cwd,
    )


# --- precedence -------------------------------------------------------------


def test_cli_flag_index_0_is_respected(tmp_path, capsys):
    """Regression: `--index 0` used to be swallowed by an ``or`` chain."""
    cfg = tmp_path / "conf.cfg"
    _write_config(str(cfg), index=5)
    cli.main(["-c", str(cfg), "-x", "0"])
    out = capsys.readouterr().out.strip()
    # Golden vector: index=0, policy="", len=6 -> 374844
    assert out == "374844"


def test_cli_flag_overrides_config_when_provided(tmp_path, capsys):
    cfg = tmp_path / "conf.cfg"
    _write_config(str(cfg), index=0)
    cli.main(["-c", str(cfg), "-x", "5"])
    # Golden: index=5, policy="", len=6 -> 869881
    assert capsys.readouterr().out.strip() == "869881"


def test_cli_falls_back_to_config_when_no_flag(tmp_path, capsys):
    cfg = tmp_path / "conf.cfg"
    _write_config(str(cfg), index=3)
    cli.main(["-c", str(cfg)])
    # Golden: index=3, policy="", len=6 -> 555522
    assert capsys.readouterr().out.strip() == "555522"


def test_cli_empty_string_policy_is_respected(tmp_path, capsys):
    """Regression: `--policy ""` used to be swallowed by an ``or`` chain."""
    cfg = tmp_path / "conf.cfg"
    _write_config(str(cfg), index=0, policy="some-policy")
    cli.main(["-c", str(cfg), "-p", "", "-x", "0"])
    # Golden: index=0, policy="", len=6 -> 374844
    assert capsys.readouterr().out.strip() == "374844"


# --- error handling ---------------------------------------------------------


def test_cli_missing_activation_key_exits_1(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["-c", str(tmp_path / "does-not-exist.cfg")])
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "activation key must be provided" in err


def test_cli_invalid_activation_key_exits_1(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["-k", "QVKYC-FM6KO-SY6F7-TR22X", "-x", "0"])
    assert exc.value.code == 1
    assert "Invalid activation key" in capsys.readouterr().err


# --- security hardening -----------------------------------------------------


def test_auto_update_writes_config_with_0600_perms(tmp_path, capsys):
    cfg = tmp_path / "conf.cfg"
    _write_config(str(cfg), index=3, auto_update=True, mode=0o644)
    cli.main(["-c", str(cfg)])
    # File must now be exactly rw-------
    mode = stat.S_IMODE(os.stat(str(cfg)).st_mode)
    assert mode == 0o600, "expected 0600, got {:o}".format(mode)


def test_auto_update_bumps_index_and_persists(tmp_path, capsys):
    cfg = tmp_path / "conf.cfg"
    _write_config(str(cfg), index=3, auto_update=True)
    cli.main(["-c", str(cfg)])
    # Re-read the file and check index bumped.
    import configparser
    parsed = configparser.ConfigParser()
    parsed.read(str(cfg))
    assert parsed.getint("MobilePASS", "index") == 4


def test_warn_on_loose_config_permissions(tmp_path, capsys):
    cfg = tmp_path / "conf.cfg"
    _write_config(str(cfg), mode=0o644)
    cli.main(["-c", str(cfg), "-x", "0"])
    err = capsys.readouterr().err
    assert "warning" in err.lower()
    assert "644" in err


def test_no_warning_on_tight_config_permissions(tmp_path, capsys):
    cfg = tmp_path / "conf.cfg"
    _write_config(str(cfg), mode=0o600)
    cli.main(["-c", str(cfg), "-x", "0"])
    err = capsys.readouterr().err
    assert err == ""


def test_atomic_write_does_not_leak_tempfile(tmp_path, capsys):
    cfg = tmp_path / "conf.cfg"
    _write_config(str(cfg), index=3, auto_update=True)
    cli.main(["-c", str(cfg)])
    # No .mobilepasser.*.tmp fragments left behind.
    leaks = [p.name for p in tmp_path.iterdir() if p.name.startswith(".mobilepasser.")]
    assert leaks == [], "leaked temp files: %r" % (leaks,)


# --- console script entry point --------------------------------------------


def test_console_script_entry_point_exists():
    """The ``mobilepasser`` executable should be installed by the package."""
    # Search PATH first, then the sibling of the current Python interpreter
    # (which is where console scripts land in a venv even if PATH isn't set).
    entry = shutil.which("mobilepasser") or os.path.join(
        os.path.dirname(sys.executable), "mobilepasser"
    )
    if not os.path.exists(entry):
        pytest.skip("mobilepasser console script is not installed")
    proc = subprocess.run(
        [entry, "-k", EXAMPLE_KEY, "-x", "0"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "374844"
