# Imports
import math
from lib import *

def floorRoot(n: int, s: int) -> int:
    """
    Finds the specified powered root of an integer and returns the resulting float's floor value.
    """
    
    b = n.bit_length()
    p = math.ceil(b/s)
    x = 2**p
    while x > 1:
        y = (((s - 1) * x) + (n // (x**(s-1)))) // s
        if y >= x:
            return x
        x = y
    return 1
    
def RSA_Broadcast_Attack(message: bytes, rsa0: object, rsa1: object, rsa2: object) -> bytes:
    """
    Uses the Chinese Remainder Theorem (CRT) to break e=3 RSA given three ciphertexts of the same plaintext.
    This attack could be easily coded to work also when a different number of ciphertexts is provided.
    Check here for reference: https://crypto.stanford.edu/pbc/notes/numbertheory/crt.html
    """

    # Obtain the N from the public keys of the RSA objects.
    n0 = rsa0.pub[1]
    n1 = rsa1.pub[1]
    n2 = rsa2.pub[1]
    
    # Encrypt the integer of the message via all three RSA objects.
    plainnum = int.from_bytes(message, "big")
    c0 = rsa0.encryptnum(plainnum)
    c1 = rsa1.encryptnum(plainnum)
    c2 = rsa2.encryptnum(plainnum)
    
    # Can't do N/n0 for ms0 instead because floating point operations arent accurate
    N = n0 * n1 * n2
    ms0 = n1 * n2
    ms1 = n0 * n2
    ms2 = n0 * n1
    
    r0 = (c0 * ms0 * mod_inverse(ms0, n0))
    r1 = (c1 * ms1 * mod_inverse(ms1, n1))
    r2 = (c2 * ms2 * mod_inverse(ms2, n2))
    
    R = (r0 + r1 + r2) % N
    m = floorRoot(R, 3)
    
    return m.to_bytes((m.bit_length() + 7) // 8, "big")
    
def main():
	message = "This is RSA Broadcast Attack"
	assert RSA_Broadcast_Attack(message.encode(), RSA(256), RSA(256), RSA(256)).decode("utf-8") == message
	
	return

if __name__ == "__main__":
	main()
