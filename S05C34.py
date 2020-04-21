# Imports
import os
import random
import hashlib
from Crypto.Cipher import AES
from lib import *

def parameter_injection_attack(alice: object, bob: object):
    block_size = AES.block_size
    # A -> M
    A = alice.gen_public_key()
    # M -> B
    A = alice.p
    # B -> M
    B = bob.gen_public_key()
    # M -> A
    B = bob.p
    
    # A -> M
    msg = b"Hello there!"
    s_a = hashlib.sha1(str(alice.gen_shared_secret_key(B)).encode()).digest()[:AES.block_size]
    iv = os.urandom(16)
    cipher_a = AES_CBC_encrypt(msg, iv, s_a) + iv
    
    # M -> B
    
    # B -> M
    s_b = hashlib.sha1(str(bob.gen_shared_secret_key(A)).encode()).digest()[:16]
    a_iv = cipher_a[-AES.block_size:]
    a_msg = AES_CBC_decrypt(cipher_a[:-AES.block_size], iv, s_b)
    print("A sent:", PKCS7_unpad(a_msg))
    iv = os.urandom(16)
    cipher_b = AES_CBC_encrypt(a_msg, iv, s_b) + iv
    
    # M -> A
    
    # Finding the key after replacing A and B with p is, in fact, very easy.
    # Instead of (B^a % p) or (A^b % p), the shared secret key of the exercise became (p^a % p)
    # and (p^b % p), both equal to zero!
    mitm_key = hashlib.sha1(b'0').digest()[:AES.block_size]
    
    mitm_iv_a = cipher_a[-block_size:]
    mitm_msg_a_read = AES_CBC_decrypt(cipher_a[:-block_size], mitm_iv_a, mitm_key)
    print("MITM MSG A:", PKCS7_unpad(mitm_msg_a_read))
    
    mitm_iv_b = cipher_b[-block_size:]
    mitm_msg_b_read = AES_CBC_decrypt(cipher_b[:-block_size], mitm_iv_b, mitm_key)
    print("MITM MSG B:", PKCS7_unpad(mitm_msg_b_read))
    
def main():

	# Given
	p = 37
	g = 5
	
	alice = DiffieHellman(g, p)
	bob = DiffieHellman(g, p)

	parameter_injection_attack(alice, bob)
	
	return
	
if __name__ == "__main__":
	main()
