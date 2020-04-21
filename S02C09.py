def PKCS7_pad(plaintext: bytes, block_size: int) -> bytes:
    """
    Pad the given text upto the length of given block_size following PKCS7 norms.
    """
    if len(plaintext) == block_size:
        return plaintext
    pad = block_size - len(plaintext) % block_size
    plaintext += (pad.to_bytes(1,"big"))*pad
    return plaintext
    
def main():

	# Given
	plaintext = "YELLOW SUBMARINE"
	target_bytes = b"YELLOW SUBMARINE\x04\x04\x04\x04"
	block_size = 20
	
	assert PKCS7_pad(plaintext.encode(), block_size) == target_bytes
	
	return
	
if __name__=="__main__":
	main()
