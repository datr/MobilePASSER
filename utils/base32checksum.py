import base32

def validateAndNormalize(encoded_string):
	if len(encoded_string.strip()) == 0:
		return encoded_string

	checksum = 0
	normalized_string = ""

	index = -1
	for character in encoded_string:
		if not base32.isBase32Character(character):
			continue

		index = index + 1
		character_value = base32.characterValue(character)
		ordinal_value = ord(character.upper())
		if ordinal_value == 48:
			ordinal_value = 79
		if ordinal_value == 49:
			ordinal_value = 73

		if index % 5 == 4:
			if character_value != checksum % 32:
				return ""
			else:
				checksum = 0
		else:
			normalized_string += character
			checksum += ordinal_value * (1 + index % 5)

	return normalized_string