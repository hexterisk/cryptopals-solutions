# Imports
import os
import random
from Crypto.Cipher import AES
from lib import *

def AES_ECB_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypts a plaintext with AES ECB Mode.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    text = PKCS7_pad(plaintext, len(key))
    return cipher.encrypt(PKCS7_pad(text, len(key)))
    
def AES_CBC_encrypt(plaintext: bytes, IV: bytes, key: bytes) -> bytes:
    """
    Encrypts a plaintext with AES CBC Mode.
    AES ECB is the block cipher encryption of choice.
    Refer https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC) for the formulae.
    """
    previous = IV
    keysize = len(key)
    ciphertext = b""
    xored = b""
    
    for i in range(0, len(plaintext), keysize):
        xor_list = [(b1 ^ b2).to_bytes(1, "little") for b1, b2 in zip(PKCS7_pad(plaintext[i:i+keysize], keysize), previous)]
        xored = b"".join(xor_list)
        cipher = AES_ECB_encrypt(xored, key)
        ciphertext += cipher
        previous = cipher
        
    return ciphertext
    
def main():
	key = os.urandom(16)

	# Enter a repeating text.
	text = open("8.txt").read()

	# Prepend and append random bytes to the text    
	plaintext = os.urandom(random.randint(5,11))
	plaintext += text.encode()
	plaintext += os.urandom(random.randint(5,11))

	flag = random.randint(0,1)
	if flag == 1:
		print("Encrypting using AES ECB Encryption.")
		ciphertext = AES_ECB_encrypt(plaintext, key)
	else:
		print("Encrypting using AES CBC Encryption.")
		ciphertext = AES_CBC_encrypt(plaintext, os.urandom(AES.block_size), key)
		
	if detect_AES_ECB(ciphertext):
		print("Ciphertext is AES ECB encrypted.")
	else:
		print("Ciphertext is AES CBC encrypted.")
		
	return

if __name__=="__main__":
	main()
