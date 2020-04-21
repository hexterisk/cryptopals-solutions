# Imports
import random
from lib import *

class RSA_server(RSA):
    """
    Extends the RSA class to verify that no ciphertext passes through more than once.
    """
    
    decrypted = []
    
    def get_public_key(self: object) -> tuple:
        return self.pub
    
    def decrypt_check(self: object, ciphertext: bytes) -> bytes:
        if ciphertext in self.decrypted:
            raise Exception("This ciphertext has already been deciphered before!")
        self.decrypted.append(ciphertext)
        return self.decrypt(ciphertext)
        
def unpadded_message_recovery(ciphertext: bytes, rsa_server: object) -> bytes:
    """
    Modifies ciphertext and recovers plaintext from an RSA server.
    """
    
    (E, N) = rsa_server.get_public_key()
    S = random.randint(1, N)
    while True:
        if S % N > 1:
            break
    
    modified_ciphertext = (pow(S, E, N) * ciphertext) % N
    
    modified_plaintext = rsa_server.decrypt_check(modified_ciphertext)
    recovered_plaintext_int = (int.from_bytes(modified_plaintext, "big") * mod_inverse(S, N) % N)
    
    return (recovered_plaintext_int).to_bytes((recovered_plaintext_int.bit_length() + 7) // 8, "big")
    
def main():
	
	rsa_server = RSA_server(256)
	plaintext = "Unpadded message"
	ciphertext = rsa_server.encrypt(plaintext.encode())
	
	assert(unpadded_message_recovery(ciphertext, rsa_server).decode("utf-8") == plaintext)
	
	return
	
if __name__ == "__main__":
	main()
