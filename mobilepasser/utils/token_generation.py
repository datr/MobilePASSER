"""MobilePASS key derivation and counter-based token generation."""

import hashlib
import hmac

from .activation_code import ActivationCode


def KDF1(hash, secret, iv, start_position, key_length):
    """Derive key bytes using the KDF1 counter, starting at zero."""
    key = bytearray(start_position)
    counter = 0
    while key_length > 0:
        digest = hash.copy()
        digest.update(secret)
        digest.update(counter.to_bytes(4, "big"))
        if iv:
            digest.update(iv)
        block = digest.digest()[:key_length]
        key.extend(block)
        key_length -= len(block)
        counter += 1
    return key


def get_key(entropy, policy):
    secret = entropy + policy.encode("utf-8")
    return KDF1(hashlib.sha256(), secret, b"", 0, 32)


def long_to_byte_array(long_num):
    """Encode the token counter as an unsigned 64-bit, big-endian value."""
    return long_num.to_bytes(8, "big")


def truncated_value(h):
    digest = bytes.fromhex(h)
    offset = digest[-1] & 0x0f
    return int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff


def generate_mobilepass_token(activation_key, index, policy="", length=6):
    """Generate the token for a zero-based index; the caller tracks the index."""
    code = ActivationCode(activation_key)
    key = get_key(code.getEntropy().tobytes(), policy)
    return generate_token_from_key(key, index, length)


def generate_token_from_key(key, index, length=6):
    """Generate an OTP from an already-derived Android key."""
    if not 0 <= index < 2**64:
        raise ValueError("Index must be an unsigned 64-bit integer.")
    if length < 1:
        raise ValueError("OTP length must be positive.")
    if len(key) != 32:
        raise ValueError("The imported OTP key must contain 32 bytes.")

    message = long_to_byte_array(index)
    digest = hmac.new(key, message, hashlib.sha256).hexdigest()
    value = truncated_value(digest) % (10**length)
    return f"{value:0{length}d}"
