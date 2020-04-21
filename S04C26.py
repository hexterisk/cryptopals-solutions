# Imports
import os
from lib import *

def encryptor(text: bytes, key: bytes, nonce: int) -> bytes:
    """
    Prepends the string to given text and encrypts with CTR.
    """
    
    # Given
    prepend_string = "comment1=cooking%20MCs;userdata="
    append_string = ";comment2=%20like%20a%20pound%20of%20bacon"

    plaintext =  (prepend_string.encode() + text + append_string.encode()).replace(b';', b'";"').replace(b'=', b'"="')
    ciphertext = CTR(plaintext, key, nonce)
    return ciphertext
    
def decryptor(byte_string: bytes, random_key: bytes, nonce: int) -> bool:
	"""
    Decrypts the ciphertext via AES CTR Mode and checks if admin is set to true.
    """
    decrypted_string = CTR(byte_string, random_key, nonce)
    if b';admin=true;' in decrypted_string:
        return True
    else:
        return False
        
def main():

	target_bytes = b";admin=true;"
	random_key = os.urandom(16)
	nonce = 0

	modified_string = b""

	# we take out prefix length and then combine the recovered
	# keystream from that offset onwards with inut text to produce
	# the required string
	prefix_length = len(os.path.commonprefix([encryptor(b'AAAA', random_key, nonce), encryptor(b'', random_key, nonce)]))
	print("Prefix length: ", prefix_length)

	dummy_input = b"heytheremama"
	ciphertext = encryptor(dummy_input, random_key, nonce)
	null_cipher = encryptor(b'\x00'*len(ciphertext), random_key, nonce)
	recovered_keystream = null_cipher[prefix_length:len(ciphertext)]

	injected_bytes = b""
	for i in range(len(target_bytes)):
		injected_bytes += (target_bytes[i] ^ recovered_keystream[i]).to_bytes(1, "big")

	modified_ciphertext = ciphertext[:prefix_length] + injected_bytes + ciphertext[prefix_length + len(injected_bytes):]
	
	assert decryptor(modified_ciphertext, random_key, nonce) == True
	
	return
	
if __name__=="__main__":
	main()
