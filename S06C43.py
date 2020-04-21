# Imports
import random
import hashlib
from Crypto.Util.number import getPrime
from lib import *

class DSA:
    """
    Implements the DSA public key encryption / decryption.
    """
    
    DEFAULT_P = int("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76"
                    "c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232"
                    "c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
    DEFAULT_Q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    DEFAULT_G = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389"
                    "b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c88"
                    "7892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)
        
    def __init__(self: object, p = DEFAULT_P, q = DEFAULT_Q, g = DEFAULT_G):
        self.p = p
        self.q = q
        self.g = g
        self.x, self. y = self._per_user_key()
        self.pvt, self.pub = self.x, self.y
        
    def _per_user_key(self: object):
        x = random.randint(1, self.q - 1)
        y = pow(self.g, x, self.p)
        return x, y
    
    def H(self: object, message: bytes) -> bytes:
        return int(hashlib.sha1(message).hexdigest(), 16)
    
    def key_distribution(self: object) -> tuple:
        return self.pub
    
    def generate_signature(self: object, message: bytes) -> (int, int):
        
        while True:
            k = random.randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q
            if r == 0:
                continue
                
            s = (mod_inverse(k, self.q) * (self.H(message) + self.x * r)) % self.q
            if s != 0:
                break
        return (r, s)
    
    def verify_signature(self: object, r: int, s: int, message: bytes) -> bool:
        if r < 0 or r > self.q:
            return False
        if s < 0 or s > self.q:
            return False
        
        w = mod_inverse(s, self.q)
        u1 = (self.H(message) * w) % self.q
        u2 = (r * w) % self.q
        
        v1 = pow(self.g, u1, self.p)
        v2 = pow(self.y, u2, self.p)
        
        v = ((v1 * v2) % self.p) % self.q
        return v == r
        
def DSA_parameter_generation(key_length: int) -> (int, int, int):
    """
    Generates DSA parameters as described by the pseudo code on wikipedia.
    """
    # Filter object is created, iter is used to fetch values and then tuple is accessed
    modulo_list = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]    

    N = filter(lambda x:key_length in x, modulo_list).__next__()[1]
    q = getPrime(N)
    
    p = 0
    while True:
        p = getPrime(key_length)
        if (p - 1) % q == 0:
            break

    g = 1
    h = 0
    
    while True:
        h = random.randint(2, p - 2)
        g = h**((p - 1) / q)
        if g != 1:
            break
    
    return p, q, g

def DSA_x_from_k(k: int, q: int, r: int, s: int, message_int: int) -> int:
    """
    Returns the value of x as calculated using other parameters.
    """
    return (((s * k) - message_int) * mod_inverse(r, q)) % q
    
def key_recovery_from_nonce(q: int, r: int, s: int, y: int, message_int: int):
    """
    Verify if the key recovered from nonce is the same as given in question.
    """
    
    # Given
    target = "0954edd5e0afe5542a4adf012611a91912a3ec16"
    
    # This loop goes over all possibilities.
    for k in range(2**16):
        x = DSA_x_from_k(k, q, r, s, message_int)
        
        # [2:] tp skip the 0x
        if hashlib.sha1(hex(x)[2:].encode()).hexdigest() == target:
            return x
    return 0
    
def main():
	# Given
	message = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
	# Used to verify if our implementation works correctly
	q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
	r = 548099063082341131477253921760299949438196259240
	s = 857042759984254168557880549501802188789837994940
	y = int("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a0808"
		    "4056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec56828"
		    "0ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)
	q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
	r = 548099063082341131477253921760299949438196259240
	s = 857042759984254168557880549501802188789837994940
	y = int("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a0808"
		    "4056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec56828"
		    "0ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)

	dsa = DSA()
	key = key_recovery_from_nonce(q, r, s, y, dsa.H(message.encode()))
	if key != 0:
		print("> Brute force successful.\nPrivate key:", key)
	else:
		print("> Brute force unsucessful.")
	
	return

if __name__ == "__main__":
	main()
