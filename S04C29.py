# Imports
import os
import struct
from lib import *

key = os.urandom(16)

def md_pad(message: bytes) -> bytes:
    """
    Pads the message in accordance with SHA1 padding.
    """
    ml = len(message) * 8
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    message += struct.pack('>Q', ml)
    return message
    
def validate(modified_message: bytes, new_md: bytes) -> bool:
    """
    Verifies the MAC .
    """
    
    global key
    
    if sha1_mac(key, modified_message) == new_md:
        return True
    return False
    
def sha1_length_extension_attack(message: bytes, original_md: bytes, payload: bytes) -> (bytes, bytes):
    """
    Perform the SHA1 length extension attack.
    """
    
    global key
    
    for key_length in range(20):
        h = struct.unpack('>5I', bytes.fromhex(original_md))
        modified_message = md_pad(b'A'*key_length + message)[key_length:] + payload
        new_md = sha1(payload, (len(modified_message) + key_length)*8, h[0], h[1], h[2], h[3], h[4])
        if validate(modified_message, new_md):
            print("> Length extension attack successful.")
            return modified_message, new_md
            break
            
def main():
	
	# Given
	message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	payload = b";admin=true"
	
	original_md = sha1_mac(key, message.encode())
	modified_message, new_md = 				sha1_length_extension_attack(message.encode(), original_md, payload)
	
	assert payload in modified_message
	
	return

if __name__=="__main__":
	main()
