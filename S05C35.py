# Imports
import os
import hashlib
from Crypto.Cipher import AES
from lib import *

def malicious_g_attack():
    """
    Simulates the break of Diffie-Hellman with negotiated groups by using malicious 'g' parameters.
    """
    
    p = DiffieHellman.DEFAULT_P
    return_vals = []

    # This loops over the values proposed for "g" by the question.
    for g in [1, p, p - 1]:

        # Step 1: the MITM changes the default g sent by Alice to Bob with a forced value.
        alice = DiffieHellman()
        bob = DiffieHellman(g=g)

        # Step 2: Bob receives this forced g and sends an ACK to Alice.

        # Step 3: Alice computes A and sends it to the MITM (thinking of Bob).
        A = alice.gen_public_key()

        # Step 4: Bob computes B and sends it to the MITM (thinking of Alice).
        B = bob.gen_public_key()

        # Step 5: Alice sends her encrypted message to Bob (without knowledge of MITM).
        _msg = b"Hello, how are you?"
        _a_key = hashlib.sha1(str(alice.gen_shared_secret_key(B)).encode()).digest()[:16]
        _a_iv = os.urandom(AES.block_size)
        a_question = AES_CBC_encrypt(_msg, _a_iv, _a_key) + _a_iv

        # Step 6: Bob receives the message sent by Alice (without knowing of the attack)
        # However, this time Bob will not be able to decrypt it, because (if I understood the
        # challenge task correctly) Alice and Bob now use different values of g.

        # Step 7: the MITM decrypts the Alice's question.
        mitm_a_iv = a_question[-AES.block_size:]

        # When g is 1, the secret key is also 1.
        if g == 1:
            mitm_hacked_key = hashlib.sha1(b'1').digest()[:16]
            mitm_hacked_message = AES_CBC_decrypt(a_question[:-AES.block_size], mitm_a_iv, mitm_hacked_key)

        # When g is equal to p, it works the same as in the S5C34 attack (the secret key is 0).
        elif g == p:
            mitm_hacked_key = hashlib.sha1(b'0').digest()[:16]
            mitm_hacked_message = AES_CBC_decrypt(a_question[:-AES.block_size], mitm_a_iv, mitm_hacked_key)

        # When g is equal to p - 1, the secret key is (-1)^(ab), which is either (+1 % p) or (-1 % p).
        # We can try both and later check the padding to see which one is correct.
        else:

            for candidate in [str(1).encode(), str(p - 1).encode()]:
                mitm_hacked_key = hashlib.sha1(candidate).digest()[:16]
                mitm_hacked_message = AES_CBC_decrypt(a_question[:-AES.block_size], mitm_a_iv, mitm_hacked_key)
                if PKCS7_padded(mitm_hacked_message):
                    mitm_hacked_message = PKCS7_unpad(mitm_hacked_message)
                    break
        print(mitm_hacked_message)
        
def main():

	malicious_g_attack()
	
	return
	
if __name__ == "__main__":
	main()
