# coding=utf-8
"""Unit tests for the base32 and base32-checksum helpers."""

from mobilepasser.utils import base32, base32_checksum


def test_isBase32Character_letters_and_digits():
    assert base32.isBase32Character("A")
    assert base32.isBase32Character("Z")
    assert base32.isBase32Character("2")
    assert base32.isBase32Character("7")
    # '0' and '1' would be invalid in classic base32 (avoided due to
    # O/I confusion), but the SafeNet variant substitutes them for O/I.
    # The isBase32Character check reads the raw table without the
    # substitution, so '0' and '1' report False; characterValue() applies
    # the substitution.
    assert not base32.isBase32Character("0")
    assert not base32.isBase32Character("1")
    assert not base32.isBase32Character("!")
    assert not base32.isBase32Character(" ")


def test_characterValue_substitution_0_to_O_and_1_to_I():
    assert base32.characterValue("0") == base32.characterValue("O")
    assert base32.characterValue("1") == base32.characterValue("I")


def test_decode_produces_expected_bit_length():
    # 16 base32 chars * 5 bits = 80 bits
    bb = base32.decode("QVKYCFM6KOSY6F7T")
    assert len(bb) == 80


def test_checksum_valid_key_normalizes_to_16_chars():
    # The example key contains a checksum char every 5th position.
    normalized = base32_checksum.validateAndNormalize("QVKYC-FM6KO-SY6F7-TR22W")
    assert len(normalized) == 16


def test_checksum_tampered_key_returns_empty_string():
    # Flipping the final checksum char to something the check rejects
    # should yield "".
    normalized = base32_checksum.validateAndNormalize("QVKYC-FM6KO-SY6F7-TR22X")
    assert normalized == ""


def test_checksum_empty_input_returns_empty():
    assert base32_checksum.validateAndNormalize("") == ""
    assert base32_checksum.validateAndNormalize("   ") == "   "
