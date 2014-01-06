import hmac;
import base64;
import array;
import binascii;
import re;
from array import array

import hashlib

# I ported the KDF1 algorithm from the bouncycastle library that shipped with
# the app as the python libraries that included this function seemed to be
# returning different values.
def KDF1(hash, secret, iv, start_position, key_length): #key should be passed by reference
	counter_start = 0
	counter = counter_start

	digest_size = hash.digest_size
	digests_required = (int) ((key_length + digest_size - 1) / digest_size)
	digest_counter = 0

	key = bytearray()

	while True:
		if digest_counter >= digests_required:
			return key

		hash.update(secret)

		# In java the counter was being cast to a byte before being passed to the hash update
		# function. Java uses narrowing primitive conversion for this type of casting which
		# only preserves the last byte. So it needed to do some bit math to preserve the whole
		# counter. This is what we're trying to replicate here.
		# See: http://stackoverflow.com/questions/2458495/how-are-integers-casted-to-bytes-in-java
		hash.update(bytes(chr((counter >> 24) & 0xff)))
		hash.update(bytes(chr((counter >> 16) & 0xff)))
		hash.update(bytes(chr((counter >> 8) & 0xff)))
		hash.update(bytes(chr(counter & 0xff)))

		if iv != "":
			hash.update(iv)

		digest = hash.digest()

		if (key_length > digest_size):
			key[start_position:start_position+digest_size] = digest[0:digest_size]
			start_position += digest_size
			key_length -= digest_size
		else:
			key[start_position:start_position+key_length] = digest[0:key_length]

		counter += 1
		digest_counter += 1

def validate_and_normalize(activation_code):
	if activation_code == "":
		return ""

	activation_code = activation_code.strip().upper()

	if len(activation_code) == 0:
		return ""

	normalized_code = ""
	for c in activation_code:
		if c == '0':
			c = 'O';
		if c == '1':
			c = 'I'

		if re.match("[A-Z2-7=]", c) is not None:
			normalized_code += c

	return normalized_code

def base32_lookup(character):
	base32_encoding = {'A':0, 'B':1, 'C':2, 'D':3, 'E':4, 'F':5, 'G':6, 'H':7, 'I':8,
	                   'J':9, 'K':10, 'L':11, 'M':12, 'N':13, 'O':14, 'P':15, 'Q':16,
	                   'R':17, 'S':18, 'T':19, 'U':20, 'V':21, 'W':22, 'X':23, 'Y':24,
	                   'Z':25, '2':26, '3':27, '4':28, '5':29, '6':30, '7':31}

	return base32_encoding[character]

def get_entropy(activation_code):
	
	normalized_code = validate_and_normalize(activation_code)
	print normalized_code

	if normalized_code == "":
		raise Exception("Invalid activation code provided.")

	bits = ""

	# We're only interested in the first 16 chracters as they encode the entity string.
	for c in [ normalized_code[i:i+1] for i in range(0, 15) ]:
		# Lookup the base32 value for each charachter, convert it to it's binary
		# representation (padding it to 5 places where necessary) and append it on to
		# the bits string.
		base32_value = base32_lookup(c)
		bits += "{0:05b}".format(base32_value)

	print bits

	# Split the string at every 8 bits to form bytes and convert them back into ints.
	bytes = [ bits[i:i+8] for i in range(0, len(bits), 8) ]
	bytes = [ int(x, 2) for x in bytes]

	print bytes

	# Finally create a bytesarray from the list of ints.
	return bytearray(bytes)

def get_key(entropy, policy):
	secret = entropy

	if len(policy) != 0:
		policy_bytes = bytearray(policy, "ascii")
		print binascii.hexlify(policy_bytes)
		secret.extend(policy_bytes)

	print binascii.hexlify(secret)

	hash = hashlib.new('sha256')

	return KDF1(hash, secret, bytearray(), 0, 32)

def long_to_byte_array(long_num):
    """
    helper function to convert a long number into a byte array
    """
    byte_array = array('B')
    for i in reversed(range(0, 8)):
        byte_array.insert(0, long_num & 0xff)
        long_num >>= 8
    return byte_array

def truncated_value(h):
    bytes = map(ord, h)
    offset = bytes[-1] & 0xf
    v = (bytes[offset] & 0x7f) << 24 | (bytes[offset+1] & 0xff) << 16 | \
            (bytes[offset+2] & 0xff) << 8 | (bytes[offset+3] & 0xff)
    return v

key = "QVKYC-FM6KO-SY6F7-TR22W"
policy = "17840159"

entropy = get_entropy(key)
key = get_key(entropy, policy) #<-- This line has been verified.

print binascii.hexlify(key)

#message = long_to_byte_array(0)
message = "1"

h = hmac.new(key, message, hashlib.sha256).hexdigest()
h = truncated_value(h)
h = h % (10**6)
print '%0*d' % (6, h)   # 374844
