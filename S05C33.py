# Imports
import os
import struct
import random
from lib import *

class DiffieHellman():
    """
    Implements the Diffie-Helman key exchange. Each class is a party, which has his secret key (usually
    referred to as lowercase a or b) shares the public key (usually referred to as uppercase A or B) and can
    compute the shared secret key between itself and another party, given their public key, assuming that
    they are agreeing on the same p and g.
    """

    DEFAULT_G = 2
    DEFAULT_P = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b225'
                    '14a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f4'
                    '4c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc20'
                    '07cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed5'
                    '29077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)

    def __init__(self: object, g=DEFAULT_G, p=DEFAULT_P):
        self.g = g
        self.p = p
        self._secret_key = random.randint(0, p - 1)
        self.shared_key = None

    def gen_public_key(self: object) -> int:
        return pow(self.g, self._secret_key, self.p)

    def gen_shared_secret_key(self: object, other_party_public_key: int) -> int:
        if self.shared_key is None:
            self.shared_key = pow(other_party_public_key, self._secret_key, self.p)
        return self.shared_key
        
def main():
	
	# Given
	p = 37
	g = 5
	
	# Alice
	a = random.randint(0, 100)
	A = (g**a) % p

	# Bob
	b = random.randint(0, 100)
	B = (g**b) % p
	
	session_key_Alice = (B**a) % p
	session_key_Bob = (A**b) % p

	assert session_key_Alice == session_key_Bob
	
	client1 = DiffieHellman()
	client2 = DiffieHellman()

	assert client1.gen_shared_secret_key(client2.gen_public_key()) == client2.gen_shared_secret_key(client1.gen_public_key())
	
	return
	
if __name__ == "__main__":
	main()
