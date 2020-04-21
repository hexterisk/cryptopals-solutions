# Imports
from lib import *

def main():
	# Given
	inf = open("4.txt", "r")
	hex_data = inf.read()

	# Creates a list of lines taken from the file.
	byte_strings = []
	for line in hex_data.split():
		byte_line = bytes.fromhex(line)
		byte_strings.append(byte_line)
		
	plaintext = ""
	max_score = 0

	# Runs the previous code against all lines in the file.
	for line in byte_strings:
		result = single_byte_xor_score(line)
		cur_score = result['score']
		testtext = result['message']
		if cur_score > max_score:
		    max_score = cur_score
		    plaintext = testtext

	print("Recovered string:\n", plaintext)
        
	return
	
if __name__=="__main__":
	main()
