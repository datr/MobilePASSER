import hashlib

import base32
import base32_checksum
from activation_payload_v1 import ActivationPayloadV1


class InvalidActivationKey(Exception):
	pass


class MissingActivationKey(Exception):
	pass


class ActivationCode:

	def __init__(self, code):
		if len(code) == 0:
			raise MissingActivationKey("Activation key is required")

		self.payloads = []

		if self.isValidLegacyActivationCode(code):
			self.legacy = True
			self.payloads.append(ActivationPayloadV1(self.entropy, 1))
		else:
			self.legacy = False
			code = self.validateAndNormalize(code)

			if not code:
				raise InvalidActivationKey("Invalid activation key")

			value = base32.decode(code)

			if len(value) < 100:
				raise InvalidActivationKey("Invalid activation key")

			if not self.checkErrorDetection(value):
				raise InvalidActivationKey("Invalid activation key")

			bit_length = ActivationPayloadV1.getBitLength()
			self.payloads.append(ActivationPayloadV1(value[0:bit_length]))


	def isValidLegacyActivationCode(self, code):
		normalized_code = base32_checksum.validateAndNormalize(code)

		if len(normalized_code) == 16:
			self.entropy = base32.decode(normalized_code)

			if (len(self.entropy) == 80):
				return True

		return False

	def validateAndNormalize(self, code):
		string = code.strip()
		normalized_code = ""

		for character in string:
			if base32.isBase32Character(character):
				normalized_code += character

		return normalized_code

	def checkErrorDetection(self, value):
		computed_code = self.computeErrorCode(value[0:-8])
		error_byte = value[-8:].uint

		return computed_code == error_byte

	def computeErrorCode(self, value):
		remainder = len(value) % 8
		if remainder != 0:
			for i in range(8 - remainder):
				value.append("0b0")

		hash = hashlib.new('sha256')
		hash.update(value.tobytes())
		digest = hash.digest()
		return ord(digest[-1])

	def getEntropy(self):
		if self.legacy:
			return self.entropy
		else:
			payload = self.payloads[0]
			return payload.getEntropy()
