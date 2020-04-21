# Imports
import base64
from lib import *

def CTR_keystream_generator(key: bytes, nonce: int) -> bytes:
    """
    Generates keystream based on given key and nonce.
    Uses AES ECB Mode to encrypt the nonce+counter block.
    """
    counter = 0
    # 8 byte because format says 64bit.
    nonce_bytes = nonce.to_bytes(8, "little")
    
    while True:
        counter_bytes = counter.to_bytes(8, "little")
        # Keep getting 16byte block from the encryption function.
        keystream_block = AES_ECB_encrypt(nonce_bytes + counter_bytes, key)
        yield from keystream_block
        counter += 1
        
def CTR(string: bytes, key: bytes, nonce: int) -> bytes:
    """
    Encrypts a plaintext with AES CTR Mode.
    """
    # Generate the keystream based on key and nonce.
    keystream = CTR_keystream_generator(key, nonce)
    
    if len(string) == 0:
        return b""
    else:
        return xor_bytes(string, keystream)
        
def main():
	# Given
	b64_string = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	key = "YELLOW SUBMARINE"
	nonce = 0
	
	decoded_string = base64.b64decode(b64_string)
	byte_text = CTR(decoded_string, key.encode(), 0)
	print(byte_text.decode("utf-8"))
	
	return
	
if __name__=="__main__":
	main()
