# Imports
from Crypto.Cipher import AES

def detect_AES_ECB(ciphertext: bytes) -> int:
    """
    Detect if the AES ECB encryption mode was used for creating the given ciphertexts.
    Returns the maximum number of repititions occuring for any particular block.
    """
    blocks = [ciphertext[i:i+AES.block_size] for i in range(0, len(ciphertext), AES.block_size)]
    return len(blocks)-len(set(blocks))

def main():

	# Given
	inf = open("8.txt", "r")
	data = inf.read()

	# Create a list of ciphertexts obtained from the file in byte format.
	hex_data = data.split('\n')
	ciphertext_list = [bytes.fromhex(line.strip()) for line in hex_data]

	# Iterate over all the ciphertexts to find out the ciphertext with maximum repititions of a block.
	max_score = 0
	text_ECB = ""

	for cipher in ciphertext_list:
		score = detect_AES_ECB(cipher)
		if score > max_score:
		    max_score = score
		    text_ECB = cipher
		    
	print("Number of repitions: {}".format(max_score))	
	print("ECB ciphered text index: {0}/{1}".format(ciphertext_list.index(text_ECB), len(ciphertext_list)))
	
	return

if __name__=="__main__":
	main()
