#!/usr/bin/env python
# coding=utf-8

import argparse
import os
import sys

import ConfigParser

from utils.activation_code import InvalidActivationKey, MissingActivationKey
from utils.token_generation import generate_mobilepass_token


CONFIG_FILE = os.path.expanduser("~/.mobilepasser.cfg")
INDEX = 0
POLICY = ''
LENGTH = 6
UPDATE = False

parser = argparse.ArgumentParser(description='A reimplementation of the MobilePASS client in Python.')
parser.add_argument('-c', '--config-file', type=str, default=CONFIG_FILE,
                    help='Path to the configuration file.')
parser.add_argument('-k', '--activation-key', type=str,
                    help='The string the MobilePass client generated.')
parser.add_argument('-x', '--index', type=int,
                    help='The index of the token to generate.')
parser.add_argument('-p', '--policy', type=str,
                    help='Policy for the token.')
parser.add_argument('-l', '--otp-length', type=int,
                    help='Length of the returned OTP.')
parser.add_argument('-a', '--auto-update-index', action="store_true",
                    help='Automatically bump the index by 1 and save to config file.')

args = parser.parse_args()
Config = ConfigParser.ConfigParser({
    'index': str(INDEX),
    'policy': POLICY,
    'otp_length': str(LENGTH),
    'auto_update_index': str(UPDATE)
})

def main():
    key = None
    index = INDEX
    policy = POLICY
    length = LENGTH
    update = UPDATE

    Config.read(args.config_file)
    if Config.has_section('MobilePASS'):
        if Config.has_option('MobilePASS', 'activation_key'):
            key = Config.get('MobilePASS', 'activation_key')
        index = Config.getint('MobilePASS', 'index')
        policy = Config.get('MobilePASS', 'policy')
        length = Config.getint('MobilePASS', 'otp_length')
        update = Config.getboolean('MobilePASS', 'auto_update_index')

    key = args.activation_key or key
    index = args.index or index
    policy = args.policy or policy
    length = args.otp_length or length
    update = args.auto_update_index or update

    if not key:
        sys.stderr.write('An activation key must be provided.\n')
        sys.exit(1)

    try:
        print generate_mobilepass_token(key, int(index), policy, int(length))
    except (InvalidActivationKey, MissingActivationKey) as e:
        sys.stderr.write(e.message + '\n')
        sys.exit(1)

    # Increment the index and save to config if the auto_update_index flag is set
    if update:
        Config.set('MobilePASS', 'index', int(index) + 1)
        cfgfile = open(CONFIG_FILE, 'w')
        Config.write(cfgfile)
        cfgfile.close()


if __name__ == "__main__":
    main()
