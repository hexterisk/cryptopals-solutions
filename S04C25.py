# Imports
import os
import base64
import itertools

from lib import *

def edit(ciphertext: bytes, key: bytes, offset: int, newtext: bytes, nonce: int) -> bytes:
    """
    Seek into the ciphertext at the given offset and edit the ciphertext to add the newtext's cipher at the offset.
    """
    keystream = b""
    # Obtain the keystream used to encrypt in the AES CTR Mode.
    # Encrypting newtext to be inserted at offset requires CTR keystream at that offset too.
    stream = CTR_keystream_generator(key, nonce)
    for i in itertools.islice(stream, offset, offset+len(newtext)):
        keystream += i.to_bytes(1, "big")
    
    # Get the cipher for newtext.
    append_cipher = xor_bytes(newtext, keystream)
    
    # Append the cipher of newtext to original cipher.
    result = ciphertext[:offset] + append_cipher
    if len(result) < len(ciphertext):
        return result + ciphertext[len(result):]
    return result
    
def main():

	# Given
	data = open("25.txt", "r").read()
	
	random_key = os.urandom(16)
	nonce = 0
	
	# if you give text as \x00 it gives out keystream, 
	# xors keystream with 0 and thus can decode keystream 
	# by using offset as 0
	recovered_bytes = base64.b64decode(data)

	random_key = os.urandom(16)
	nonce = 0

	ciphertext = CTR(recovered_bytes, random_key, nonce)
	recovered_keystream = edit(ciphertext, random_key, 0, b'\x00'*len(ciphertext), nonce)
	deciphered_bytes = xor_bytes(ciphertext, recovered_keystream)
	
	assert deciphered_bytes == recovered_bytes
	
	print("Given data recovered successfully.")
	
	return
   
if __name__=="__main__":
	main()
