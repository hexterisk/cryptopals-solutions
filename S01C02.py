# Imports
from base64 import b64encode

def xor_bytes(enc1: bytes, enc2: bytes) -> bytes:
    """
    xor_bytes computes the xor of two byte strings and returns the final value.
    """
    cipher = b"".join([bytes(b1^b2 for b1, b2 in zip(enc1, enc2))])
    return cipher

def main():

	# Given
	hex_string = "1c0111001f010100061a024b53535009181c"
	key_string = "686974207468652062756c6c277320657965"
	target_string = "746865206b696420646f6e277420706c6179"

	byte_string = bytes.fromhex(hex_string)
	key_byte_string = bytes.fromhex(key_string)
    
    # Verify the solution.
	result = xor_bytes(byte_string, key_byte_string).hex() 
	assert result == target_string
	
	return
		
if __name__ == "__main__":
	main()
