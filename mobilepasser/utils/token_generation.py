# coding=utf-8
"""HOTP token generation for MobilePASS activation keys."""

import array
import hashlib
import hmac
from typing import Union

from .activation_code import ActivationCode


BytesLike = Union[bytes, bytearray, memoryview]


# I ported the KDF1 algorithm from the bouncycastle library that shipped with
# the app as the python libraries that included this function seemed to be
# returning different values.
def KDF1(
    hash,
    secret: BytesLike,
    iv: BytesLike,
    start_position: int,
    key_length: int,
) -> bytearray:
    """IEEE P1363a KDF1 with a big-endian 32-bit counter (Bouncy Castle flavor)."""
    counter = 0

    digest_size = hash.digest_size
    digests_required = int((key_length + digest_size - 1) / digest_size)
    digest_counter = 0

    key = bytearray()

    while True:
        if digest_counter >= digests_required:
            return key

        hash.update(secret)

        # In Java the counter was cast to a byte before being passed to the
        # hash update function. Java uses narrowing primitive conversion for
        # this type of casting which only preserves the last byte. So we do
        # some bit math to preserve the whole counter, feeding it in four
        # single-byte updates (big-endian).
        # See: http://stackoverflow.com/questions/2458495/how-are-integers-casted-to-bytes-in-java
        hash.update(bytes([(counter >> 24) & 0xff]))
        hash.update(bytes([(counter >> 16) & 0xff]))
        hash.update(bytes([(counter >> 8) & 0xff]))
        hash.update(bytes([counter & 0xff]))

        if iv:
            hash.update(iv)

        digest = hash.digest()

        if key_length > digest_size:
            key[start_position:start_position + digest_size] = digest[0:digest_size]
            start_position += digest_size
            key_length -= digest_size
        else:
            key[start_position:start_position + key_length] = digest[0:key_length]

        counter += 1
        digest_counter += 1


def get_key(entropy: bytes, policy: str) -> bytearray:
    secret = bytearray(entropy)

    if len(policy) != 0:
        secret += policy.encode("utf_8")

    hash = hashlib.new("sha256")
    return KDF1(hash, bytes(secret), bytearray(), 0, 32)


def long_to_byte_array(long_num: int) -> "array.array[int]":
    """helper function to convert a long number into a byte array"""
    byte_array = array.array("B")
    for _ in reversed(range(0, 8)):
        byte_array.insert(0, long_num & 0xff)
        long_num >>= 8
    return byte_array


def truncated_value(h: str) -> int:
    # In Python 3, str.decode('hex') no longer exists; use bytes.fromhex()
    # which is the semantic equivalent on a hex-string HMAC digest.
    bytes_ = bytearray(bytes.fromhex(h))
    offset = bytes_[-1] & 0xf
    v = (
        (bytes_[offset] & 0x7f) << 24
        | (bytes_[offset + 1] & 0xff) << 16
        | (bytes_[offset + 2] & 0xff) << 8
        | (bytes_[offset + 3] & 0xff)
    )
    return v


def generate_mobilepass_token(
    activation_key: str,
    index: int,
    policy: str = "",
    length: int = 6,
) -> str:
    """Generate the HOTP token at ``index`` for the given ``activation_key``.

    ``activation_key`` is the string the MobilePASS client generated.

    ``index`` is a 0-based index of the token to generate. The first
    generated token is for index=0, the second for index=1, and so on. It
    is the caller's responsibility to keep track of the current index.
    """
    message = long_to_byte_array(index)

    code = ActivationCode(activation_key)
    entropy = code.getEntropy().tobytes()
    key = get_key(entropy, policy)

    h = hmac.new(bytes(key), message.tobytes(), hashlib.sha256).hexdigest()
    truncated = truncated_value(h)
    truncated = truncated % (10 ** length)
    return "%0*d" % (length, truncated)
