# Imports
import math
import random
from Crypto.Util.number import getPrime
from lib import *

def mod_inverse(a: int, n: int) -> int: 
    """
    Computes the multiplicative inverse of a modulo n using the extended Euclidean algorithm.
    """
    
    t, r = 0, n
    new_t, new_r = 1, a

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise Exception("a is not invertible")
    if t < 0:
        t = t + n

    return t
    
class RSA:
    """
    Implementation of the RSA (Rivest–Shamir–Adleman) algorithm.
    """
    
    def __init__(self: object, keysize: int):
        e = 3
        et = 0
        n = 0

        while math.gcd(e, et) != 1:
            p, q = getPrime(keysize // 2), getPrime(keysize // 2)
            et = ((p - 1) * (q - 1)) // math.gcd(p - 1, q - 1)
            n = p * q

        d = mod_inverse(e, et)
        
        self.pub = (e, n)
        self.pvt = (d, n)

    def encrypt(self: object, message: bytes, byteorder="big") -> int:
        (e, n) = self.pub
        data = int.from_bytes(message, byteorder)
        
        if data < 0 or data >= n:
            raise ValueError(str(data) + ' out of range')
            
        return pow(data, e, n)
    
    def encryptnum(self: object, m: int) -> int:
        (e, n) = self.pub
        if m < 0 or m >= n:
            raise ValueError(str(m) + ' out of range')
        return pow(m, e, n)
    
    def decrypt(self: object, ciphertext: bytes, byteorder="big") -> bytes:
        (d, n) = self.pvt
        
        if ciphertext < 0 or ciphertext >= n:
            raise ValueError(str(ciphertext) + ' out of range')
        
        numeric_plain = pow(ciphertext, d, n)
        return numeric_plain.to_bytes((numeric_plain.bit_length() + 7) // 8, byteorder)
    
    def decryptnum(self: object, m: int) -> int:
        (d, n) = self.pvt
        if m < 0 or m >= n:
            raise ValueError(str(m) + ' out of range')
        return pow(m, d, n)
        
def main():

	rsa = RSA(1024)
	message = "Testing 1..2..3..."
	ciphertext = rsa.encrypt(message.encode())
	assert rsa.decrypt(ciphertext).decode("utf-8") == message
	
	return
	
if __name__ == "__main__":
	main()
