# Imports
import math
import base64
import decimal
from lib import *

def check_parity(ciphertext: int, rsa: object) -> int:
    """
    Returns the last bit of the number.
    """
    return rsa.decryptnum(ciphertext) & 1
    
def parity_attack(message: bytes, rsa: object) -> int:
    """
    Parity attack on RSA
    """
    
    (_, n) = rsa.pub
    ciphertext = rsa.encryptnum(int.from_bytes(message, "big"))
    
    # encrypt multiplier
    multiplier = rsa.encryptnum(2)
    
    # Initialize lower and upper bound.
    # I need to use Decimal because it allows me to set the precision for the floating point
    # numbers, which we will need when doing the binary search divisions.
    lower_bound = decimal.Decimal(0)
    upper_bound = decimal.Decimal(n)
    
    # Compute the number of iterations that we have to do
    num_iter = int(math.ceil(math.log(n, 2)))
    # Set the precision of the floating point number to be enough
    decimal.getcontext().prec = num_iter

    for _ in range(num_iter):
        ciphertext = (ciphertext * multiplier) % n
        
        # checking parity
        if check_parity(ciphertext, rsa) & 1:
            lower_bound = (lower_bound + upper_bound) / 2
        else:
            upper_bound = (lower_bound + upper_bound) / 2

    # Return the binary version of the upper_bound (converted from Decimal to int)
    return int(upper_bound).to_bytes((int(upper_bound).bit_length() + 7) // 8, "big").decode("utf-8")
    
def main():
	
	# Given
	given_string = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
	
	byte_string = base64.b64decode(given_string)
	plaintext = parity_attack(byte_string, RSA(1024))
	
	assert(plaintext == byte_string.decode("utf-8"))
	
	return

if __name__ == "__main__":
	main()
