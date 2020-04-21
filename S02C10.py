# Imports
import base64
from Crypto.Cipher import AES
from lib import *

def PKCS7_padded(text: bytes) -> bool:
    """
    Checks if the given text is padded according to the PKCS7 norms.
    """
    padding = text[-text[-1]:]
    
    # Check that all the bytes in the range indicated by the padding are equal to the padding value itself.
    return all(padding[b] == len(padding) for b in range(0, len(padding)))
    
def PKCS7_unpad(paddedtext: bytes) -> bytes:
    """
    Unpads the given text if it's padded according to PKCS7 norms.
    """
    
    # Checks if the text is padded according to PKCS7 norms.
    if PKCS7_padded(paddedtext):
        # The last byte is a padding byte.
        pad_Length = paddedtext[len(paddedtext)-1]
        # Returns the text uptil last "pad" length bytes since pad byte value is the same as number of pad bytes required.
        return paddedtext[:-pad_Length]
    else:
        return paddedtext
        
def AES_CBC_decrypt(ciphertext: bytes, IV: bytes, key: bytes) -> bytes:
    """
    Decrypts a ciphertext encrypted with AES CBC Mode.
    AES ECB is the block cipher encryption of choice.
    Refer https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC) for the formulae.
    """
    previous = IV
    keysize = len(key)
    plaintext = b""
    cipher = ""
    
    for i in range(0, len(ciphertext), keysize):
        cipher = AES_ECB_decrypt(ciphertext[i:i+keysize], key)
        xor_list = [chr(b1 ^ b2) for b1, b2 in zip(cipher, previous)]
        plaintext += "".join(xor_list).encode()
        previous = ciphertext[i:i+keysize]
        
    return plaintext

def main():

	# Given
	inf = open("10.txt", "r")
	b64_data = inf.readlines()

	key = b"YELLOW SUBMARINE"
	
	byte_string = b"".join([base64.b64decode(line.strip()) for line in b64_data])

	text = PKCS7_unpad(AES_CBC_decrypt(byte_string, b'\x00'*AES.block_size, key))
	print(text.decode("utf-8").strip('\n'))
	
	return

if __name__=="__main__":
	main()
