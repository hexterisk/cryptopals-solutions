# Imports
import os
import base64
from lib import *

def main():

	# Given
	b64_strings = open("20.txt").readlines()
	nonce = 0
	
	random_key = os.urandom(16)
	decoded_strings = [base64.b64decode(line.strip()) for line in b64_strings]
	ciphertext_list = [CTR(string, random_key, nonce) for string in decoded_strings]
	min_ciphertext_length = min(map(len, ciphertext_list))
	
	columns = []
	for i in range(min_ciphertext_length):
		line = b""
		for cipher in ciphertext_list:
		    line += cipher[i].to_bytes(1, "big")
		result = single_byte_xor_score(line)
		columns.append(result["message"])

	message = ""
	for i in range(min_ciphertext_length):
		for c in columns:
		    message += c[i]
	
	print(message)
	
	return
	
if __name__=="__main__":
	main()

