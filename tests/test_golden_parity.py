# coding=utf-8
"""Parity tests: the Python 3 port must reproduce byte-for-byte OTPs from
the original Python 2 implementation captured in ``golden_vectors.json``."""

import pytest

from mobilepasser.utils.activation_code import (
    ActivationCode,
    InvalidActivationKey,
    MissingActivationKey,
)
from mobilepasser.utils.token_generation import generate_mobilepass_token


def _otp_id(v):
    return "policy={policy!r}|len={otp_length}|idx={index}".format(**v)


def _collect_otp_vectors():
    # We can't use `golden` fixture here because ids= is evaluated at
    # collection time. Re-read the file manually.
    import json
    import os
    with open(os.path.join(os.path.dirname(__file__), "golden_vectors.json")) as f:
        return json.load(f)["otp_vectors"]


@pytest.mark.parametrize("v", _collect_otp_vectors(), ids=_otp_id)
def test_otp_matches_python2_reference(v):
    got = generate_mobilepass_token(
        v["activation_key"], v["index"], v["policy"], v["otp_length"]
    )
    assert got == v["expected_token"]


def test_activation_code_legacy_entropy_matches(
    example_legacy_key, example_legacy_entropy_hex
):
    code = ActivationCode(example_legacy_key)
    assert code.getEntropy().tobytes().hex() == example_legacy_entropy_hex


def test_activation_code_invalid_key_raises():
    # Tamper with the last character of the checksum-protected legacy key.
    with pytest.raises(InvalidActivationKey):
        ActivationCode("QVKYC-FM6KO-SY6F7-TR22X")


def test_activation_code_empty_key_raises():
    with pytest.raises(MissingActivationKey):
        ActivationCode("")
