# coding=utf-8
"""A tiny bit-level buffer used by the MobilePASS activation-key parser.

Replaces the ``bitstring`` third-party dependency with a stdlib-only
implementation. Only supports the operations actually needed by this
project:

* construction from nothing (empty buffer) or from another BitBuffer slice
* ``append(bits)`` where ``bits`` is either a "0b..." string, a single-bit
  string like "0b0"/"0b1", or another BitBuffer
* ``len(buf)`` returns the number of *bits* held
* ``buf[i:j]`` slicing returns a new BitBuffer
* ``buf.tobytes()`` returns a ``bytes`` object, MSB-first, right-padded
  with zero bits if the length is not a multiple of 8
* ``buf.int`` returns the two's-complement signed integer interpretation
* ``buf.uint`` returns the unsigned integer interpretation
"""


class BitBuffer:
    __slots__ = ("_value", "_length")

    def __init__(self, value=0, length=0):
        # ``_value`` holds the bits as an unsigned int; the MSB is bit
        # position ``_length - 1``.
        self._value = value & ((1 << length) - 1) if length > 0 else 0
        self._length = length

    # ---- construction helpers -------------------------------------------------

    @classmethod
    def _from_bit_string(cls, s):
        # Accepts "0b0101" or "0b0" / "0b1".
        if not s.startswith("0b"):
            raise ValueError("bit string must start with '0b'")
        bits = s[2:]
        if not bits:
            return cls(0, 0)
        return cls(int(bits, 2), len(bits))

    # ---- length / slicing -----------------------------------------------------

    def __len__(self):
        return self._length

    def __getitem__(self, item):
        if not isinstance(item, slice):
            raise TypeError("BitBuffer only supports slicing, not int indexing")
        start, stop, step = item.indices(self._length)
        if step != 1:
            raise ValueError("BitBuffer slicing does not support step != 1")
        if stop <= start:
            return BitBuffer(0, 0)
        new_length = stop - start
        # We want the bit range [start, stop) counted from the MSB (bit 0 is
        # leftmost). Convert to LSB-based shift.
        shift = self._length - stop
        mask = (1 << new_length) - 1
        return BitBuffer((self._value >> shift) & mask, new_length)

    # ---- mutation -------------------------------------------------------------

    def append(self, other):
        """Append bits from a "0b..." string or another BitBuffer."""
        if isinstance(other, str):
            other = BitBuffer._from_bit_string(other)
        elif not isinstance(other, BitBuffer):
            raise TypeError(
                "BitBuffer.append expects a '0b...' str or BitBuffer, got %r"
                % type(other).__name__
            )
        self._value = (self._value << other._length) | other._value
        self._length += other._length

    # ---- conversion -----------------------------------------------------------

    def tobytes(self):
        """MSB-first bytes, right-padded with zeros to a full byte boundary."""
        if self._length == 0:
            return b""
        pad = (-self._length) % 8
        total_bits = self._length + pad
        value = self._value << pad
        num_bytes = total_bits // 8
        return value.to_bytes(num_bytes, byteorder="big")

    @property
    def uint(self):
        return self._value

    @property
    def int(self):
        if self._length == 0:
            return 0
        sign_bit = 1 << (self._length - 1)
        if self._value & sign_bit:
            # negative in two's-complement
            return self._value - (1 << self._length)
        return self._value

    # ---- debug helpers --------------------------------------------------------

    def __repr__(self):
        return "BitBuffer(bits={0:0{1}b}, length={1})".format(
            self._value, self._length
        )
