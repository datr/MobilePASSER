MobilePASSER
============

MobilePASSER is a reimplementation of the MobilePASS client in Python 3.

Installation
------------

Requires Python 3.11 or newer and [uv](https://docs.astral.sh/uv/).
The project defaults to Python 3.13 via `.python-version`.

```sh
uv sync --locked
uv run mobilepasser --help
```

Dependencies are defined in `pyproject.toml` and pinned in `uv.lock`.
uv manages the Python interpreter and the local `.venv` environment.
Both bitstring 4.3+ and 5.x are supported; the lockfile selects bitstring 5.

To install the command independently of the project environment:

```sh
uv tool install .
mobilepasser --help
```

Usage
-----

```text
usage: mobilepasser [-h] [-c CONFIG_FILE] [-k ACTIVATION_KEY] [-x INDEX] [-p POLICY]
                    [-l OTP_LENGTH] [-a]

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        Path to the configuration file.
  -k ACTIVATION_KEY, --activation-key ACTIVATION_KEY
                        The string the MobilePass client generated.
  -x INDEX, --index INDEX
                        The index of the token to generate.
  -p POLICY, --policy POLICY
                        Policy for the token.
  -l OTP_LENGTH, --otp-length OTP_LENGTH
                        Length of the returned OTP.
  -a, --auto-update-index
                        Automatically bump the index by 1 and save to config
                        file.
```

```sh
uv run mobilepasser -k YOUR_ACTIVATION_KEY -x 0
uv run mobilepasser
```

`uv run python -m mobilepasser` and `uv run python cli.py` also work.

Configuration
-------------
The configuration file is read from `~/.mobilepasser.cfg`. Copy
`examples/mobilepasser.cfg` there and replace the example activation key with
your own. Existing configuration files remain compatible.

Command-line values override configuration values, including index `0` and an
empty policy (`-p ''`). Without a configuration file, the defaults are index `0`,
an empty policy, six OTP digits and no automatic index update.

Set `auto_update_index = True` or pass `-a` to save the next index after token
generation. If the file does not exist, `-a` creates it with the next index;
an activation key supplied on the command line is not saved to the file.

Development
-----------

Run the regression tests and build the package:

```sh
uv run python -m unittest discover -s tests -v
uv build
```

Android backup import
---------------------

The inspected Android storage format can be imported with its original
app-specific Android ID. A rooted device connected through an authorized ADB
connection can supply both the Properties file and this ID directly:

```sh
uv run mobilepasser-import-android --from-adb \
  --otp-length 6 --output ~/.mobilepasser.cfg
```

The Properties file is read from
`/data/user/0/securecomputing.devices.android.controller/app_SAFENET_TOKEN_MP3`.
If exactly one token file is present, it is selected automatically. If several
are present, the command lists their filenames and requires `--token-file NAME`.
`--serial DEVICE` selects the ADB device and `--user ID` selects the Android user.
Properties are read into memory without creating a local backup copy.

A local Properties file can also be supplied; `--from-adb` then reads only
the Android ID from the device:

```sh
uv run mobilepasser-import-android /path/to/token.properties \
  --from-adb --otp-length 6 --output ~/.mobilepasser.cfg
```

The importer supports the inspected device-binding mode `2`, tokens with or
without a PIN, and 32-byte OTP keys. It verifies
the metadata, token-label and wrapping-key HMACs before exporting the key.
Existing output files are never overwritten; new files have permissions
`0600`. Android data and counters are read without being changed. Neither the
Android ID nor the recovered key is printed.

For a token protected by a PIN, add `--pin` to the import command. The PIN is
prompted without echo, preserves leading zeroes, and is used only to decrypt
the Android backup. It is never saved in the configuration or printed. A
wrong PIN fails the wrapping-key HMAC check and no output is created. Without
`--pin`, the importer uses the app's internal default for tokens without a PIN.

The exported configuration contains the decrypted OTP key and does not
require a PIN during subsequent code generation; `--pin` is an import option,
not encryption of the exported configuration.

The resulting configuration uses `secret_key` instead of `activation_key`:
the recovered key is already derived and must not pass through KDF1 again.
An explicit `-k` still selects activation-key generation.

**Confirm the token's generation mode and digit count before using it.**
The importer copies the stored event counter and requires an explicit OTP
length; it does not automatically translate Android policies or implement
time-based/challenge-response generation. For a confirmed counter-based
HMAC-SHA256 token, generate a code and advance the local counter with:

```sh
uv run mobilepasser -a
```

The Android and Python counters evolve independently. Further code generation
in Android can make the imported counter stale. The import itself does not
verify a login with the authentication server.

Read-only format inspection is also available:

```sh
uv run python tools/android_backup_info.py /path/to/token.properties
```

