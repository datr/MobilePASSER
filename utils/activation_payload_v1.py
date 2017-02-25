import sys

class ActivationPayloadV1:
	
	def __init__(self, activation_code, compatability_level=False):
		if compatability_level != False:
			self.payloadID = 1
			self.entropy = activation_code
			self.capabilityLevel = compatability_level
			self.initialized = True

		else:
			self.entropy = activation_code[0:80]
			self.compatabilityLevel = 1 + activation_code[80:85].int
			self.initialized = True

	def getEntropy(self):
		return self.entropy

	@staticmethod
	def getBitLength():
		return 85;
