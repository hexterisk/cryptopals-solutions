# Imports
import os
import base64
import random
from Crypto.Cipher import AES
from lib import *

def encryptor(IV: bytes, key: bytes) -> (bytes, bytes):
    """
    Chose a random base64 encoded string and encrypt via AES CBC Mode.
    """
    
    # Given
    b64_strings = [
        b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
	]

    index = random.randint(0, len(b64_strings)-1)
    selected_string = b64_strings[index]
    ciphertext = AES_CBC_encrypt(selected_string, IV, key)
    return selected_string, ciphertext
    
def decryptor(ciphertext: bytes, IV: bytes, key: bytes) -> bool:
    """
    Decrypt the given ciphertext via AES CBC Mode and check if padding is valid.
    """
    plaintext = AES_CBC_decrypt(ciphertext, IV, key)
    if PKCS7_padded(plaintext):
        return True
    else:
        return False
        
def modify_block(IV: bytes, guessed_byte: bytes, padding_len: int, found_plaintext: bytes) -> bytes:
    """
    Creates a forced block of the ciphertext, ideally to be given as IV to decrypt the following block.
    The forced IV will be used for the attack on the padding oracle CBC encryption.
    """
    
    block_size = len(IV)

    # Get the index of the first character of the padding.
    index_of_forced_char = len(IV) - padding_len

    # Using the guessed byte given as input, try to force the first character of the
    # padding to be equal to the length of the padding itself.
    forced_character = IV[index_of_forced_char] ^ guessed_byte ^ padding_len

    # Form the forced ciphertext by adding to it the forced character...
    output = IV[:index_of_forced_char] + bytes([forced_character])

    # ...and the characters that were forced before (for which we already know the plaintext).
    m = 0
    for k in range(block_size - padding_len + 1, block_size):

        # Force each of the following characters of the IV so that the matching characters in
        # the following block will be decrypted to "padding_len".
        forced_character = IV[k] ^ ord(found_plaintext[m]) ^ padding_len
        output += bytes([forced_character])
        m += 1

    return output
    
def cbc_padding_attack(ciphertext: bytes, IV: bytes, key: bytes, decryptor: callable) -> bytes:

    block_size = len(IV)
    
    # Create ciphertext blocks, with IV prepended to the ciphertexts.
    # The prepended IV enables us to decrypt the first block of ciphertext.
    plaintext = ""
    num_blocks = len(ciphertext)//block_size
    ciphertext_blocks = [IV] + [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    
    # This loop goes over the cipher blocks.
    for i in range(1, num_blocks+1):
        plain_block = ""
        base_block = ciphertext_blocks[i-1] 
        target_block = ciphertext_blocks[i]
                
        # This loop goes over every byte in a block.
        for j in range(1, block_size+1):
            possible_last_bytes = []
            # This loop goes over all possible values for a byte.
            for k in range(256):
                
                mod_block = modify_block(base_block, k, j, plain_block)                
                check = decryptor(target_block, mod_block, key)
                # Make a list of all values that satisfy the padding.
                if check == True:
                    possible_last_bytes += bytes([k])
             
            # If more than one possible bytes have been found, then verify their validity by checking the next byte.
            if len(possible_last_bytes) != 1:
                for byte in possible_last_bytes:
                    for k in range(256):
                        
                        mod_block = modify_block(base_block, k, j+1, chr(byte)+plain_block)                
                        
                        check = decryptor(target_block, mod_block, key)
                        if check == True:
                            possible_last_bytes = [byte]
                            break
            # Append the decrypted byte to the plain block.                
            plain_block = chr(possible_last_bytes[0]) + plain_block
        # Append the decrypted block to plaintext.
        plaintext += plain_block
    
    return PKCS7_unpad(plaintext.encode())
    
def main():
	
	keysize = AES.block_size
	random_key = os.urandom(keysize)
	IV = os.urandom(keysize)
	
	selected_string, ciphertext = encryptor(IV, random_key)
	plaintext = cbc_padding_attack(ciphertext, IV, random_key, decryptor)
	result = base64.b64decode(plaintext).decode("utf-8")
	assert selected_string == plaintext
	print(result)
	
	return
	
if __name__=="__main__":
	main()
