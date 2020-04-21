def repeated_xor(text: bytes, key: bytes) -> bytes:
    """
    Performs xor between given text and key. If the length is unequal, key repeats.
    """
    quotient, remainder = divmod(len(text), len(key))
    return bytes([x ^ y for x, y in zip(text, bytes(key * quotient + key[:remainder]))])

def main():

	# Given
	plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key = "ICE"
	target_string = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	byte_string = plaintext.encode()
	bytekey = key.encode()

	ciphertext = repeated_xor(byte_string, bytekey)
	
	# Verify the solution.
	assert target_string == ciphertext.hex()
	
	return
	
if __name__=="__main__":
	main()
