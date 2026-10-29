"""Command-line interface for MobilePASSER."""

import argparse
import configparser
import os
import sys

from .utils.activation_code import InvalidActivationKey, MissingActivationKey
from .utils.token_generation import generate_mobilepass_token, generate_token_from_key


CONFIG_FILE = os.path.expanduser("~/.mobilepasser.cfg")
INDEX = 0
POLICY = ""
LENGTH = 6
UPDATE = False


def build_parser():
    parser = argparse.ArgumentParser(
        description="A reimplementation of the MobilePASS client in Python."
    )
    parser.add_argument("-c", "--config-file", default=CONFIG_FILE,
                        help="Path to the configuration file.")
    parser.add_argument("-k", "--activation-key",
                        help="The string the MobilePass client generated.")
    parser.add_argument("-x", "--index", type=int,
                        help="The index of the token to generate.")
    parser.add_argument("-p", "--policy", help="Policy for the token.")
    parser.add_argument("-l", "--otp-length", type=int,
                        help="Length of the returned OTP.")
    parser.add_argument("-a", "--auto-update-index", action="store_true",
                        help="Automatically bump the index by 1 and save to config file.")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    config = configparser.ConfigParser(defaults={
        "index": str(INDEX),
        "policy": POLICY,
        "otp_length": str(LENGTH),
        "auto_update_index": str(UPDATE),
    }, interpolation=None)

    try:
        loaded_files = config.read(args.config_file, encoding="utf-8")
        section = config["MobilePASS"] if config.has_section("MobilePASS") else config["DEFAULT"]
        key = args.activation_key if args.activation_key is not None else section.get("activation_key")
        secret_key = section.get("secret_key") if args.activation_key is None else None
        index = args.index if args.index is not None else section.getint("index")
        policy = args.policy if args.policy is not None else section.get("policy")
        length = args.otp_length if args.otp_length is not None else section.getint("otp_length")
        update = args.auto_update_index or section.getboolean("auto_update_index")

        if not key and not secret_key:
            config_status = "" if loaded_files else " (not found or unreadable)"
            raise MissingActivationKey(
                "No activation key or imported secret_key found.\n"
                f"Configuration file: {args.config_file}{config_status}\n"
                "Pass --activation-key KEY, or select a configuration with "
                "--config-file PATH containing activation_key or secret_key "
                "in the [MobilePASS] section."
            )

        if secret_key:
            token = generate_token_from_key(bytes.fromhex(secret_key), index, length)
        else:
            token = generate_mobilepass_token(key, index, policy, length)

        if update:
            if not config.has_section("MobilePASS"):
                config.add_section("MobilePASS")
            config.set("MobilePASS", "index", str(index + 1))
            with open(args.config_file, "w", encoding="utf-8") as config_file:
                config.write(config_file)
    except (InvalidActivationKey, MissingActivationKey, ValueError,
            OSError, configparser.Error) as error:
        print(str(error), file=sys.stderr)
        return 1

    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
