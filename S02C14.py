# Imports
import os
import math
import base64
import random
from Crypto.Cipher import AES
from lib import *

# Given
b64_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

# Pseudo random key and prefix string.
random_key = os.urandom(16)
random_string = os.urandom(random.randint(0,255))

def AES128_harder(text: bytes) -> bytes:
    """
    Oracle function to return ciphertext for random string and secret string, prepended and appended respectively, to plaintext.
    """
    global b64_string, random_key, random_string
    
    secret_string = base64.b64decode(b64_string)
    plaintext = random_string + text + secret_string
    cipher = AES_ECB_encrypt(plaintext, random_key)
    return cipher
        
def break_AES_ECB_harder(keysize: int, encryptor: callable) -> bytes:
    """
    Breaks AES ECB encryption for the encryptor function provided.
    """
        
    # Padding required to bridge gap between randomstringlength and block.
    padding = 0
    random_blocks = 0
    cipher_length = len(encryptor(b''))
    prefix_length = len(os.path.commonprefix([encryptor(b'AAAA'), encryptor(b'')]))
    print("Prefix length: ", prefix_length)
    
    # Find number of random blocks.
    for i in range(int(cipher_length/keysize)):
        if prefix_length < i*keysize:
            random_blocks = i
            break
    print("Random blocks: ", random_blocks)
    
    # Find number of byte padding required.
    base_cipher = encryptor(b'')
    for i in range(1, keysize):
        new_cipher = encryptor(b'A'*i)
        new_prefix_length = len(os.path.commonprefix([base_cipher, new_cipher]))
        if new_prefix_length > prefix_length:
            padding = i - 1
            break
        base_cipher = new_cipher
    print("Number of bytes of padding required: ", padding)
    
    # To get added string length since 0 len input is provided, all cipher is of added string.
    deciphered = b""
    ciphertext = encryptor(deciphered)
    # Because of one block increase due to addition of padding.
    run = len(ciphertext) + keysize
    
    # Should start after prefix random_blocks because till then it value will be same for original cipher and templated cipehr since same prepended string will be compared.
    for i in range(keysize * random_blocks + 1, run+1):
        template = b'A'*(run - i + padding)
        cipher = encryptor(template)
        for j in range(256):
            #print(i, j)
            text = template + deciphered + j.to_bytes(1, "little")
            c = encryptor(text)
            # Keysize used to refer to the block whose last character is made to be the appended string's 1st char.
            if c[run-keysize:run] == cipher[run-keysize:run]:
                deciphered += chr(j).encode()
                break
    return PKCS7_unpad(deciphered)
    
def main():
	keysize = 16
	byte_text = break_AES_ECB_harder(keysize, AES128_harder)
	print("\nDeciphered string:\n")
	print(byte_text.decode("utf-8").strip())
	
if __name__=="__main__":
	main()
