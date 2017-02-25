#!/usr/bin/env python
# coding=utf-8

import argparse
import os
import sys
import ConfigParser

from utils.token_generation import generate_mobilepass_token

CONFIG_FILE = os.path.expanduser("~") + "/.mobilepasser.cfg"


parser = argparse.ArgumentParser(description='A reimplementation of the MobilePASS client in Python.')
parser.add_argument('-k', '--activation-key', type = str,
                    help = 'The string the MobilePass client generated.')
parser.add_argument('-x', '--index', type = int, default = 0,
                    help = 'The index of the token to generate.')
parser.add_argument('-p', '--policy', type = str, default = '',
                    help = 'Policy for the token.')
parser.add_argument('-l', '--otp-length', type = int, default = 6,
                    help = 'Length of the returned OTP.')

args = parser.parse_args()
Config = ConfigParser.ConfigParser()

def read_config():
    Config.read(CONFIG_FILE)
    if not Config.has_section('MobilePASS') or \
        not(Config.has_option('MobilePASS', 'activation_key') and \
            Config.has_option('MobilePASS', 'index')):
        raise ValueError('''Configuration file is missing required parameters.\nMake sure it looks something like this:\n
            [MobilePASS]
            activation_key="QVKYC-FM6KO-SY6F7-TR22W"
            policy=""
            index=0
            otp_length=6
            ''')

if args.activation_key == None and not os.path.exists(CONFIG_FILE):
    raise RuntimeError('Must provide an activation key or create a config file. See --help for more information.')

if args.activation_key == None and len(sys.argv) > 1:
    raise ValueError('Can not provide arguments without specifying an activation key. See --help for more information.')

if args.activation_key:
    key = args.activation_key
    index = args.index
    policy = args.policy
    length = args.otp_length
else:
    read_config()
    key = Config.get('MobilePASS', 'activation_key')
    index = Config.get('MobilePASS', 'index')
    policy = Config.get('MobilePASS', 'policy')
    length = Config.get('MobilePASS', 'otp_length')

print generate_mobilepass_token(key or '', int(index or 0), policy or '', int(length))

# Increment the index and save to config if we are using the config file
if len(sys.argv) == 1:
    Config.set('MobilePASS', 'index', int(index) +1)
    cfgfile = open(CONFIG_FILE, 'w')
    Config.write(cfgfile)
    cfgfile.close
