# Imports
import os
import time
import math
import random
from lib import *

def MT19937_keystream_generator(seed: int) -> bytes:
    """
    Generate keystream for MT19937
    """
    # Verify that the seed is atmost 16 bit long.
    assert math.log2(seed) <= 16
    
    prng = MT19937(seed)
    while True:
        number = prng.extract_number()
        yield from number.to_bytes(4, "big")
        
def MT19937_CTR(string: str, seed: int) -> bytes:
    """
    Encrypts a plaintext with MT19937 CTR Mode.
    """
    # Verify that the seed is an integer.
    assert isinstance(seed, int)
    
    keystream = MT19937_keystream_generator(seed)
    if len(string) == 0:
        return b""
    else:
        return bytes([(b1 ^ b2) for b1, b2 in zip(string, keystream)])
        
def main():

	plaintext = "Hello World!"

	# append random characters before plainttext
	string = b""
	for _ in range(random.randint(0, 10)):
		i = random.randint(33, 126)
		string += chr(i).encode()
	string += plaintext.encode()

	seed = random.randint(1, 2**16)
	print("> Seed value coded to be", seed)
	cipher_bytes = MT19937_CTR(string, seed)
	deciphered_bytes = MT19937_CTR(cipher_bytes, seed)

	# verify if it can be decrypted
	assert string == deciphered_bytes

	#The number of possible keys is super small so you can just try them all. They even insist on it in the instructions: the cipher is using a 16-bits seed. It's kind of weird actually because from the specifications of MT19937 the seed seems to be 32 bits. Well even 32 bits should be small enough to crack, it would just take longer.
	for seed in range(1, 2**16):
		deciphered_bytes = MT19937_CTR(cipher_bytes, seed)
		try:
		    assert string == deciphered_bytes
		    print("> Brute force successful.\nSeed:", seed)
		    break
		except AssertionError:
		    continue
		    
	return
	
if __name__=="__main__":
	main()
