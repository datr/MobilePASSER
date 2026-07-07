# coding=utf-8
"""Unit tests for the tiny stdlib BitBuffer that replaced ``bitstring``."""

import pytest

from mobilepasser.utils.bitbuffer import BitBuffer


def test_empty_buffer():
    b = BitBuffer()
    assert len(b) == 0
    assert b.tobytes() == b""
    assert b.uint == 0
    assert b.int == 0


def test_append_bit_string_and_length():
    b = BitBuffer()
    b.append("0b10101")
    assert len(b) == 5
    assert b.uint == 0b10101


def test_append_multiple_bit_strings_concatenates_msb_first():
    b = BitBuffer()
    b.append("0b101")
    b.append("0b010")
    # Order: 101 then 010 -> 101010
    assert b.uint == 0b101010
    assert len(b) == 6


def test_tobytes_pads_right_with_zero_bits():
    # 10 bits: 1010101010 -> two bytes 10101010 10000000 = 0xAA 0x80
    b = BitBuffer()
    b.append("0b1010101010")
    assert b.tobytes() == bytes([0xAA, 0x80])


def test_slicing_returns_new_buffer():
    b = BitBuffer()
    b.append("0b11001010")
    s = b[2:6]
    assert len(s) == 4
    assert s.uint == 0b0010


def test_slicing_supports_negative_indices():
    b = BitBuffer()
    b.append("0b11110000")
    assert b[:-4].uint == 0b1111
    assert b[-4:].uint == 0b0000
    assert len(b[-4:]) == 4


def test_int_signed_interpretation():
    b = BitBuffer()
    b.append("0b111")  # 3-bit signed: -1
    assert b.int == -1
    assert b.uint == 7


def test_int_unsigned_when_msb_zero():
    b = BitBuffer()
    b.append("0b0101")
    assert b.int == 5
    assert b.uint == 5


def test_append_bitbuffer():
    a = BitBuffer()
    a.append("0b101")
    b = BitBuffer()
    b.append("0b010")
    a.append(b)
    assert a.uint == 0b101010
    assert len(a) == 6


def test_append_rejects_bad_input_type():
    b = BitBuffer()
    with pytest.raises(TypeError):
        b.append(42)


def test_getitem_rejects_non_slice():
    b = BitBuffer()
    b.append("0b1")
    with pytest.raises(TypeError):
        _ = b[0]


def test_roundtrip_bytes_via_full_bytes():
    # Full 16 bits -> two bytes
    b = BitBuffer()
    b.append("0b1101001110110001")
    assert b.tobytes() == bytes([0b11010011, 0b10110001])
