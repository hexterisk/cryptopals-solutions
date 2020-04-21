# Imports
import os
from lib import *

def check_ascii_compliance(plaintext: bytes) -> bool:
    """Returns true if all the characters of plaintext are ASCII compliant (ie are in the ASCII table)."""
    return all(c < 128 for c in plaintext)
    
def encryptor(text: bytes, IV: bytes, key: bytes) -> bytes:
    """
    Encrypts the text with AES CBC Mode.
    """
    
    # Given
    prepend_string = "comment1=cooking%20MCs;userdata="
    append_string = ";comment2=%20like%20a%20pound%20of%20bacon"
	
    plaintext = text.replace(b';', b'";"').replace(b'=', b'"="')
    ciphertext = AES_CBC_encrypt(PKCS7_pad(plaintext, len(key)), IV, key)
    return ciphertext
    
def decryptor(byte_string: bytes, IV: bytes, key: bytes) -> bool:
    """
    Decrypts the ciphertext via AES CBC Mode and checks if all characters are ASCII.
    """
    decrypted_string = AES_CBC_decrypt(byte_string, IV, key)
    print(len(decrypted_string), decrypted_string)
    if not check_ascii_compliance(decrypted_string):
        raise Exception(decrypted_string)
        
def main():
	
	keysize = 16
	random_key = os.urandom(keysize)
	IV = random_key

	plaintext = b"lorem=ipsum;test=fun;padding=dull"
	ciphertext = encryptor(plaintext, IV, random_key)
	c1 = ciphertext[:keysize]
	c2 = ciphertext[keysize:2*keysize]
	c3 = ciphertext[2*keysize:]

	try:
		decryptor(c1 + b'\x00'*16 + c1, IV, random_key)
	except Exception as e:
		decrypted_string = str(e).encode()
		p1 = decrypted_string[:keysize]
		p3 = decrypted_string[2*keysize:]
		decrypted_key = xor_bytes(p1, p3)
		print("> Key found to be:", decrypted_key)
		
		return
		
if __name__=="__main__":
	main()
