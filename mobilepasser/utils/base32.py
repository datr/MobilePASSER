# coding=utf-8
"""Base32 decoder used by the MobilePASS activation-key parser.

Note: this is *not* RFC 4648 base32. The character-value table and the
digit-substitutions (``0`` -> ``O``, ``1`` -> ``I``) mirror the original
Java implementation shipped by SafeNet.
"""

from .bitbuffer import BitBuffer

# ASCII table (offset -48) mapping each character to its 5-bit value.
# 255 marks an invalid character.
characterValues = [
    255, 255, 26, 27, 28, 29, 30, 31, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6,
    7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    255, 255, 255, 255, 255,
]


def characterValue(character):
    character_ascii_value = ord(character.upper())

    # '0' -> 'O'
    if character_ascii_value == 48:
        character_ascii_value = 79

    # '1' -> 'I'
    if character_ascii_value == 49:
        character_ascii_value = 73

    character_value_index = character_ascii_value - 48

    return characterValues[character_value_index]


def isBase32Character(character):
    character_ascii_value = ord(character)
    character_value_index = character_ascii_value - 48
    return (
        0 <= character_value_index < len(characterValues)
        and characterValues[character_value_index] != 255
    )


def decode(encoded_string):
    decoded_value = BitBuffer()

    for character in encoded_string:
        character_value = characterValue(character)
        decoded_value.append("0b{0:05b}".format(character_value))

    return decoded_value
