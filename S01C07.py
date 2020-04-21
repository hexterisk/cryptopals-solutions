# Imports
import base64
from Crypto.Cipher import AES

def AES_ECB_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts a ciphertext encrypted with AES ECB Mode.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)
    
def main():
	# Given
	inf = open("7.txt", "r")
	b64_data = inf.read()

	key = b"YELLOW SUBMARINE"
	
	byte_data = base64.b64decode(b64_data)
	byte_text = AES_ECB_decrypt(byte_data, key)

	#last 4 rubbish bytes is pkcs7 padding of \x04
	print("Decoded bytes:\n", byte_text.strip())
	
	return

if __name__=="__main__":
	main()
