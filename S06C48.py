# Imports
import os
import random
from lib import *

class RSA_PKCS1_Oracle(RSA):
    """
    Extends the RSA class by making the decryption PKCS 1.5 compliant and by adding a method
    to verify the padding of data.
    """
    
    def PKCS1_Pad(self: object, message: bytes) -> bytes:
        """
        Pads the given binary data conforming to the PKCS 1.5 format.
        """
        
        (e, n) = self.pub
        byte_length = (n.bit_length() + 7) // 8
        padding_string = os.getrandom(byte_length - 3 - len(message))
        return b"\x00\x02" + padding_string + b'\x00' + message
  
    def PKCS1_check_padding(self: object, ciphertext: int) -> bool:
        """
        Decrypts the input data and returns whether its padding is correct according to PKCS 1.5.
        """
        
        _, n = self.pub
        k = (n.bit_length() + 7) // 8
        pbytes = self.decrypt(ciphertext)
        pbytes = (b'\x00' * (k - len(pbytes))) + pbytes
        return pbytes[0:2] == b'\x00\x02'
        
def ceil(a: int, b: int) -> int:
    """
    Returns the ceil of division between two numbers.
    """
    return (a + b - 1) // b
    
def append_interval(M_narrow: list, lower_bound: int, upper_bound: int):
    """
    Append the passed bounds as an interval to the list.
    Write over the interval if tighter constraints are passed.
    Skip if it already exists.
    """
    
    # Check if there exist an interval which is overlapping with the lower_bound and
    # upper_bound of the new interval we want to append
    for i, (a, b) in enumerate(M_narrow):

        # If there is an overlap, then replace the boundaries of the overlapping
        # interval with the wider (or equal) boundaries of the new merged interval
        if not (b < lower_bound or a > upper_bound):
            new_a = min(lower_bound, a)
            new_b = max(upper_bound, b)
            M_narrow[i] = new_a, new_b
            return

    # If there was no interval overlapping with the one we want to add, add
    # the new interval as a standalone interval to the list
    M_narrow.append((lower_bound, upper_bound))
    return

def padding_oracle_attack(ciphertext: bytes, rsa: object):
    """
    Performs the padding oracle attack on RSA ciphertext.
    """
    
    # Setting initial values
    
    (e, n) = rsa.pub
    k = (n.bit_length() + 7) // 8 # byte length
    B = 2**(8 * (k - 2))
    M = [(2 * B, 3 * B - 1)]
    i = 1
    
    if not rsa.PKCS1_check_padding(ciphertext):
        #Step 1 Blinding
        while True:
            s = random.randint(0, n - 1)
            c0 = (ciphertext * pow(s, e, n)) % n
            if rsa.PKCS1_check_padding(c0):
                break

    else:
        c0 = ciphertext
        
    # Step 2 Searching for PKCS conforming messages
    while True:
        # 2a
        if i == 1:
            s = (n + 3 * B - 1) // (3 * B)
            while True:
                c = (c0 * pow(s, e, n)) % n
                if rsa.PKCS1_check_padding(c):
                    break
                s += 1

        #2b
        elif len(M) >= 2:
            while True:
                s += 1
                c = (c0 * pow(s, e, n)) % n
                if rsa.PKCS1_check_padding(c):
                    break
        
        #2c
        # Step 2.c: Searching with one interval left
        elif len(M) == 1:
            a, b = M[0]

            # Check if the interval contains the solution
            if a == b:

                # And if it does, return it as bytes
                return b'\x00' + (a).to_bytes((a.bit_length() +7) // 8, "big")

            r = ceil(2 * (b * s - 2 * B), n)
            s = ceil(2 * B + r * n, b)

            while True:
                c = (c0 * pow(s, e, n)) % n
                if rsa.PKCS1_check_padding(c):
                    break

                s += 1
                if s > (3 * B + r * n) // a:
                    r += 1
                    s = ceil((2 * B + r * n), b)

        # Step 3: Narrowing the set of solutions
        M_new = []

        for a, b in M:
            min_r = ceil(a * s - 3 * B + 1, n)
            max_r = (b * s - 2 * B) // n

            for r in range(min_r, max_r + 1):
                l = max(a, ceil(2 * B + r * n, s))
                u = min(b, (3 * B - 1 + r * n) // s)

                if l > u:
                    raise Exception('Unexpected error: l > u in step 3')

                append_interval(M_new, l, u)

        if len(M_new) == 0:
            raise Exception('Unexpected error: there are 0 intervals.')

        M = M_new
        i += 1
        
def main():

	# Given
	message = "kick it, CC"

	rsa = RSA_PKCS1_Oracle(768)
	m = rsa.PKCS1_Pad(message.encode())

	c = rsa.encrypt(m)
	assert rsa.PKCS1_check_padding(c)
	print("> Ciphertext padding verified.")
	recovered_plaintext = padding_oracle_attack(c, rsa)
	
	assert(recovered_plaintext == m)
	
	return
	
if __name__ == "__main__":
	main()
