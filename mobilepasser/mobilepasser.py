#!/usr/bin/env python3
# coding=utf-8
"""MobilePASS CLI entry point.

Sensitive data note:
    The activation key stored in the config file is the HOTP seed. Anyone
    with read access to the file can compute every future OTP for the
    associated token. This CLI enforces mode ``0600`` on any config file
    it writes and warns on stderr when it reads a config file whose
    permissions are looser than that.
"""

import argparse
import configparser
import os
import stat
import sys
import tempfile
from typing import List, Optional

from .utils.activation_code import InvalidActivationKey, MissingActivationKey
from .utils.token_generation import generate_mobilepass_token


CONFIG_FILE: str = os.path.expanduser("~/.mobilepasser.cfg")
INDEX: int = 0
POLICY: str = ""
LENGTH: int = 6
UPDATE: bool = False

# Owner read+write only. The activation key is a long-lived HOTP seed.
CONFIG_FILE_MODE: int = 0o600


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="A reimplementation of the MobilePASS client in Python."
    )
    parser.add_argument(
        "-c", "--config-file", type=str, default=CONFIG_FILE,
        help="Path to the configuration file.",
    )
    parser.add_argument(
        "-k", "--activation-key", type=str, default=None,
        help="The string the MobilePass client generated.",
    )
    parser.add_argument(
        "-x", "--index", type=int, default=None,
        help="The 0-based index of the token to generate.",
    )
    parser.add_argument(
        "-p", "--policy", type=str, default=None,
        help="Policy for the token.",
    )
    parser.add_argument(
        "-l", "--otp-length", type=int, default=None,
        help="Length of the returned OTP.",
    )
    parser.add_argument(
        "-a", "--auto-update-index", action="store_true",
        help="Automatically bump the index by 1 and save to config file.",
    )
    return parser


def _warn_if_config_is_world_readable(path: str) -> None:
    """Print a stderr warning if ``path`` exists with permissions looser than 0600."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return
    # Bits we care about: any group/other read/write/execute.
    loose_bits = (
        stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP
        | stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH
    )
    if st.st_mode & loose_bits:
        sys.stderr.write(
            "warning: {p} has permissions {mode:o}; the activation key it "
            "contains is the HOTP seed. Restrict with `chmod 600 {p}`.\n".format(
                p=path, mode=st.st_mode & 0o777
            )
        )


def _atomic_write_config(config: configparser.ConfigParser, path: str) -> None:
    """Write ``config`` to ``path`` atomically with ``0600`` permissions.

    A crash mid-write will not truncate the existing config: we write to a
    sibling temp file (same directory, same filesystem) and then ``os.replace``
    it into place, which is atomic on POSIX and Windows for files.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(
        prefix=".mobilepasser.", suffix=".tmp", dir=directory
    )
    try:
        os.fchmod(fd, CONFIG_FILE_MODE)
        with os.fdopen(fd, "w") as f:
            config.write(f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        # Clean up the temp file on failure so we don't leak plaintext-seed
        # fragments on disk.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _first_not_none(*values):
    """Return the first argument that is not ``None`` (or ``None`` if all are)."""
    for v in values:
        if v is not None:
            return v
    return None


def main(argv: Optional[List[str]] = None) -> None:
    args = _build_parser().parse_args(argv)

    _warn_if_config_is_world_readable(args.config_file)

    config = configparser.ConfigParser({
        "index": str(INDEX),
        "policy": POLICY,
        "otp_length": str(LENGTH),
        "auto_update_index": str(UPDATE),
    })
    config.read(args.config_file)

    cfg_key: Optional[str] = None
    cfg_index = INDEX
    cfg_policy = POLICY
    cfg_length = LENGTH
    cfg_update = UPDATE

    if config.has_section("MobilePASS"):
        if config.has_option("MobilePASS", "activation_key"):
            cfg_key = config.get("MobilePASS", "activation_key")
        cfg_index = config.getint("MobilePASS", "index")
        cfg_policy = config.get("MobilePASS", "policy")
        cfg_length = config.getint("MobilePASS", "otp_length")
        cfg_update = config.getboolean("MobilePASS", "auto_update_index")

    # CLI takes precedence over the config file, but only when the user
    # actually passed a value. Using ``... or ...`` would drop legitimate
    # zero/empty values (notably ``--index 0`` for the first token and
    # ``--policy ""``).
    key = _first_not_none(args.activation_key, cfg_key)
    index = _first_not_none(args.index, cfg_index)
    policy = _first_not_none(args.policy, cfg_policy)
    length = _first_not_none(args.otp_length, cfg_length)
    # ``store_true`` never yields None; OR is fine here (True beats config).
    update = args.auto_update_index or cfg_update

    if not key:
        sys.stderr.write("An activation key must be provided.\n")
        sys.exit(1)

    try:
        token = generate_mobilepass_token(key, int(index), policy, int(length))
    except (InvalidActivationKey, MissingActivationKey) as e:
        sys.stderr.write(str(e) + "\n")
        sys.exit(1)

    print(token)

    if update:
        if not config.has_section("MobilePASS"):
            config.add_section("MobilePASS")
            # Make sure at least the values we're about to persist are set,
            # otherwise ConfigParser will only serialize the DEFAULTs section.
            config.set("MobilePASS", "activation_key", key)
            config.set("MobilePASS", "policy", policy or "")
            config.set("MobilePASS", "otp_length", str(int(length)))
            config.set("MobilePASS", "auto_update_index", str(bool(update)))
        config.set("MobilePASS", "index", str(int(index) + 1))
        _atomic_write_config(config, args.config_file)


if __name__ == "__main__":
    main()
