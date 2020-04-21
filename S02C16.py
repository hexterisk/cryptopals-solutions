# Imports
import os
import random
from Crypto.Cipher import AES
from lib import *

# Given
parameter = b";admin=true;"

keysize = 16
random_key = os.urandom(keysize)
IV = os.urandom(random.randint(0,255))


def encryptor(text: bytes, IV: bytes, key: bytes) -> bytes:
    """
    Prepend and append the given strings to custom text, and encrypt via AES CBC Mode.
    """
    
    # Given
    prepend_string = "comment1=cooking%20MCs;userdata="
    append_string = ";comment2=%20like%20a%20pound%20of%20bacon"

    plaintext =  (prepend_string.encode() + text + append_string.encode()).replace(b';', b'";"').replace(b'=', b'"="')
    ciphertext = AES_CBC_encrypt(PKCS7_pad(plaintext, len(key)), IV, key)
    return ciphertext
    
def decryptor(byte_string: bytes, IV: bytes, key: bytes) -> bool:
    """
    Decrypt the given ciphertext via AES CBC Mode and check if admin is set to true.
    """
    global parameter
    
    decrypted_string = PKCS7_unpad(AES_CBC_decrypt(byte_string, IV, key))
    if parameter in decrypted_string:
        return True
    else:
        return False
        
def CBC_bit_flipping(parameter: bytes, keysize: int, encryptor: callable) -> bytes:    
    
    global random_key, IV
    
    # Padding required to bridge gap between randomstringlength and block.
    padding = 0
    random_blocks = 0


    # Find the prefix length.
    cipher_length = len(encryptor(b'', IV, random_key))
    prefix_length = len(os.path.commonprefix([encryptor(b'AAAA', IV, random_key), encryptor(b'', IV, random_key)]))
    print("Prefix length: ", prefix_length)

    # Find number of random blocks.
    for i in range(int(cipher_length/keysize)):
        if prefix_length < i*keysize:
            random_blocks = i
            break
    print("Random blocks: ", random_blocks)

    # Find number of byte padding required.
    base_cipher = encryptor(b'', IV, random_key)
    for i in range(1, keysize):
        new_cipher = encryptor(b'A'*i, IV, random_key)
        new_prefix_length = len(os.path.commonprefix([base_cipher, new_cipher]))
        if new_prefix_length > prefix_length:
            padding = i - 1
            break
        base_cipher = new_cipher
    print("Number of bytes of padding required: ", padding)

    # Flip bytes for the given string.
    input_text = b'A'*padding + b"heytheremama"
    string = parameter
    modified_string = b""
    ciphertext = encryptor(input_text, IV, random_key)
    for i in range(len(string)):
        modified_string += (ciphertext[i+(random_blocks-1)*keysize]^(input_text[i+padding]^string[i])).to_bytes(1, "big")

    modified_ciphertext = ciphertext[:(random_blocks-1)*keysize] + modified_string + ciphertext[(random_blocks-1)*keysize + len(modified_string):]
    
    return modified_ciphertext
    
def main():
	global parameter
	
	modified_ciphertext = CBC_bit_flipping(parameter, keysize, encryptor)
	print(AES_CBC_decrypt(modified_ciphertext, IV, random_key))
	
	assert decryptor(modified_ciphertext, IV, random_key) == True
	
	return

if __name__=="__main__":
	main()
