import array
import base64
import hashlib
import hmac

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

def get_entropy(activation_code):
	# Remove hyphens.
	activation_code = activation_code.replace('-', '')
	
	# Remove every 5th chracter.
	activation_code = ''.join('' if i % 5 == 0 else char for i, char in enumerate(activation_code, 1))

	return base64.b32decode(activation_code, True, "I")

def get_key(entropy, policy):
	secret = entropy

	if len(policy) != 0:
		policy_bytes = bytearray(policy, "ascii")
		secret.extend(policy_bytes)

	hash = hashlib.new('sha256')

	return KDF1(hash, secret, bytearray(), 0, 32)

def long_to_byte_array(long_num):
    """
    helper function to convert a long number into a byte array
    """
    byte_array = array.array('B')
    for i in reversed(range(0, 8)):
        byte_array.insert(0, long_num & 0xff)
        long_num >>= 8
    return byte_array

def truncated_value(h):
    bytes = bytearray(h.decode("hex"))
    offset = bytes[-1] & 0xf
    v = (bytes[offset] & 0x7f) << 24 | (bytes[offset+1] & 0xff) << 16 | \
            (bytes[offset+2] & 0xff) << 8 | (bytes[offset+3] & 0xff)
    return v

key = "QVKYC-FM6KO-SY6F7-TR22W"
policy = ""
message = long_to_byte_array(0)

entropy = get_entropy(key)
key = get_key(entropy, policy)

h = hmac.new(key, message, hashlib.sha256).hexdigest()
h = truncated_value(h)
h = h % (10**6)
print '%0*d' % (6, h)   # 374844
