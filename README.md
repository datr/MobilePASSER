MobilePASSER
============

MobilePASSER is a reimplementation of the SafeNet/Gemalto **MobilePASS** HOTP
client in modern Python. It derives one-time passwords locally from a stored
activation key — no network traffic, no calls to any vendor service.

Requirements
------------

* Python **3.8 or newer**
* No third-party runtime dependencies (uses only the standard library)

Installation
------------

From a checkout of this repository:

```
pip install .
```

Or, for development (with the test dependencies):

```
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Usage
-----

```
usage: mobilepasser [-h] [-c CONFIG_FILE] [-k ACTIVATION_KEY] [-x INDEX]
                    [-p POLICY] [-l OTP_LENGTH] [-a]

optional arguments:
  -h, --help            show this help message and exit
  -c, --config-file CONFIG_FILE
                        Path to the configuration file (default:
                        ~/.mobilepasser.cfg).
  -k, --activation-key ACTIVATION_KEY
                        The string the MobilePASS client generated.
  -x, --index INDEX     The 0-based index of the token to generate.
  -p, --policy POLICY   Policy for the token.
  -l, --otp-length OTP_LENGTH
                        Length of the returned OTP.
  -a, --auto-update-index
                        Automatically bump the index by 1 and save to config
                        file.
```

Configuration
-------------

By default the configuration is read from `~/.mobilepasser.cfg`. An example
config file is provided under `examples/`.

```ini
[MobilePASS]
activation_key = QVKYC-FM6KO-SY6F7-TR22W
index = 0
policy =
otp_length = 6
auto_update_index = True
```

Security notes
--------------

The `activation_key` in the config file is the **HOTP seed**. Anyone with read
access to the file can compute every past and future OTP for the token. This
CLI takes the following precautions:

* On write (via `--auto-update-index`), the config file is created **atomically**
  (temp file + `os.replace`) with **`0600`** permissions.
* On read, if the config file is looser than `0600` a warning is printed to
  stderr.

If you're storing an activation key on disk, ensure the file lives on a
filesystem you trust and that only your user account can read it:

```
chmod 600 ~/.mobilepasser.cfg
```

Development
-----------

Run the tests (including golden parity vectors captured from the original
Python 2 implementation):

```
pytest
```

The golden vectors live in `tests/golden_vectors.json` and pin the exact OTP
outputs of the original code across 126 combinations of `(activation_key,
index, policy, otp_length)`. The Python 3 port must reproduce these outputs
byte-for-byte.

License
-------

MIT. See [LICENSE](LICENSE).
