# Imports
from base64 import b64encode

def main():

	# Given
	hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	target_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	byte_array = bytes.fromhex(hex_string)
	base64_byte_array = b64encode(byte_array)

	# Verify the solution
	assert base64_byte_array.decode("utf-8") == target_string
	
	return
	
if __name__ == "__main__":
	main()
