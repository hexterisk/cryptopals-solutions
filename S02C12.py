# Imports
import os
import base64
import random
from Crypto.Cipher import AES
from lib import *

# Given
b64_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

random_key = os.urandom(16)

def AES128(text: bytes) -> bytes:
    """
    Oracle function to return ciphertext for secret string appended to plaintext.
    """
    global b64_string
    global random_key
    secret_string = base64.b64decode(b64_string)
    plaintext = text + secret_string
    cipher = AES_ECB_encrypt(plaintext, random_key)
    return cipher
    
def AES_ECB_keysize(AES: callable) -> int:
    """
    Returns keysize used by an AES ECB encryption function.
    """
    
    text = "A random key long enough to decode the key size used in the encryption"
    
    # Checks repetition of blocks.
    # Looks for increase in cipher length because the moment text length goes over blocksize, a new block is created of blocksize, padded.
    # Thus we can infer block size from the increase in length observed.
    for i in range(1, len(text)):
        plaintext = text[:i] + text[:i]
        cipher = AES(plaintext.encode())
        if cipher[:i] == cipher[i:2*i]:                          
            print("Key size used for the given ciphertext is {}".format(i))
            return i
          
def break_AES_ECB(keysize: int, encryptor: callable) -> bytes:
    """
    Breaks AES ECB encryption for the encryptor function provided.
    """
    deciphered = b""
    
    # To get secret string length since 0 len input is provided, ciphertext only consists of secret string.
    ciphertext = encryptor(deciphered)
    # We run the loop upto the length of the secret string since that's what we have to discover.
    run = len(ciphertext)
    
    for i in range(1, run+1):
        # Template is 'A' multiplied by number of bytes not decrytpted yet.
        template = b'A'*(run - i)
        # Gets cipher for template
        cipher = encryptor(template)
        
        for j in range(256):
            # Adds the deciphered bytes to the template
            text = template + deciphered + j.to_bytes(1, "big")
            c = encryptor(text)
            # Keysize used to refer to the block whose last character is made to be the appended string's 1st char.
            # Comparison between letters appended to the last byte and the cipher of the template only.
            if c[run-keysize:run] == cipher[run-keysize:run]:
                deciphered += chr(j).encode()
                break
    
    return PKCS7_unpad(deciphered)
    

def main():

	# Get keysize to identify block size.
	keysize = AES_ECB_keysize(AES128)

	# Decipher appended input.
	deciphered = break_AES_ECB(keysize, AES128)
	print("Given base64 encoded string was:\n{}".format(deciphered.decode("utf-8").strip('\n')))
	
	return
	
if __name__=="__main__":
	main()
            

    

