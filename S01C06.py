# Imports
from base64 import b64decode
from lib import *

def hamming_distance(text1: bytes, text2: bytes) -> int:
    """
    Calculates the Hamming Distance between the given byte strings.
    """
    
    distance = 0
    
    dec_list = [b1 ^ b2 for b1, b2 in zip(text1, text2)]
    for decimal in dec_list:
        distance += bin(decimal).count("1")
        
    if len(text1) > len(text2):
        diff = len(text1) - len(text2)
        text = text1
    else:
        diff = len(text2) - len(text1)
        text = text2
        
    for i in range(1, diff+1):
        distance += bin(text[-i]).count("1")
        
    return distance
    
def break_repeated_xor_keysize(ciphertext: bytes) -> int:
    """
    Approximates the keysize based on the hamming distance between different blocks of ciphertexts.
    Returns the keysize with least hamming distance between consecutive sets of ciphertext.
    """
    
    keysize = 0
    min_distance = 100000
    for key in range(2, 41):
        edit_distance = 0
        blocks = [ciphertext[i*key:(i+1)*key] for i in range(4)]
        for i in range(0, len(blocks)):
            for j in range(0, len(blocks)):
                edit_distance += hamming_distance(blocks[i], blocks[j])
        
        normalized_distance = edit_distance/key
        
        if normalized_distance < min_distance:
            min_distance = normalized_distance
            keysize = key
    
    return keysize
     
def main():

	# Given
	inf = open("6.txt", "r")
	b64_data = inf.read()
	byte_data = b64decode(b64_data)
	
	# Creates blocks of ciphertext in preparation of brute forcing the xor key.
	keysize = break_repeated_xor_keysize(byte_data)
	cipher_blocks = [byte_data[i:i+keysize] for i in range(0, len(byte_data), keysize)]
	#To remove the last block with less characters.
	cipher_blocks.pop()
	cipher_block_size = len(cipher_blocks[0]) 
   
	# Brute force the key, one letter at a time.
	key = ""
	for i in range(0, cipher_block_size):
		single_xor_block = b""
		
		# Construct blocks out of a fixed index from all cipher blocks.
		for block in cipher_blocks:
		    single_xor_block += (block[i]).to_bytes(1, "big")
		    
		# Apply frequency analysis to the block associated with this index.
		result = single_byte_xor_score(single_xor_block)
		testkey = result["key"]
		key += testkey
		
	print("Key:\n", key)
	print("\n\nDeciphered text:\n", repeated_xor(byte_data, key.encode()).decode("utf-8").strip())
	
	return
   
if __name__=="__main__":
	main()
