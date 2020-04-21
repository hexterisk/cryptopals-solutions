# Imports
import os
from Crypto.Cipher import AES
from lib import *

# Generating a pseudo random key.
random_key = os.urandom(16)

def parser(user: dict, encode: bool) -> dict:
    """
    Parse the given string into a dictionary of format User.
    """
    if encode == True:
        parsed_string =  "&".join(key.strip(":")+"="+val for key, val in zip(user.keys(), user.values()))
        return parsed_string.encode()
    else:
        return {key:val for key, val in (element.split('=') for element in user.split('&'))}
        
def profile_for(val: str) -> dict:
    """
    Returns a user profile for given email.
    """
    val = val.decode("utf-8")
    user = {"email:": val, "uid:": "10", "role": "user"}
    return parser(user, True)

def oracle(email: str) -> bytes:
    """
    Returns a new profile for the given email in AES ECB encrypted form.
    """
    
    global random_key
    encoded_profile = AES_ECB_encrypt(profile_for(email), random_key)
    return encoded_profile
    
def main():

	global random_key
	keysize = 16
	
    # Get encrypted bytes with "admin".
	email = b"f"*(keysize-len("email=")) + PKCS7_pad(b"admin", keysize)
	cipher = oracle(email)
	encoded_admin_bytes = cipher[keysize:keysize*2]

    # Calculate the number of blocks taken up by the text and then generate an email that completes the block so the admin parameter can be appended in the new block.
	num_blocks = int((len("&uid=10") + len("email=") + len("&role="))/keysize) + 1
	email = b"f"*(num_blocks*keysize - (len("&uid=10") + len("email=") + len("&role=")-6))+b"@gmail.com"
	cipher = oracle(email)
    # Add the encoded paramter bytes to the ciphertext.
	modified_cipher = cipher[:48] + encoded_admin_bytes

	cracked_cipher_plaintext = parser(PKCS7_unpad(AES_ECB_decrypt(modified_cipher, random_key)).decode("utf-8"), False)
	
	assert cracked_cipher_plaintext['role'] == 'admin'
	
	print("Privilege escalated profile:\n", cracked_cipher_plaintext)
	
	return

if __name__=="__main__":
	main()
