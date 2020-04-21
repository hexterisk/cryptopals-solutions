# Imports
import time
import random
from lib import *

def int_to_bit_list(x: int) -> list:
    """
    Convert an integer to it's binary form, and return the bits in a list.
    """
    return [int(b) for b in "{:032b}".format(x)]

def bit_list_to_int(l: list) -> int:
    """
    Receive a list of bits and convert it into an integer.
    """
    return int(''.join(str(x) for x in l), base=2)

def invert_shift_mask_xor(y: int, direction: str, shift: int, mask=0xFFFFFFFF) -> int:
    """
    Shift, mask and xor the given integer in the specified direction with the passed mask.
    """
    y = int_to_bit_list(y)
    mask = int_to_bit_list(mask)

    if direction == "left":
        y.reverse()
        mask.reverse()
    else:
        assert direction == "right"

    x = [None]*32
    for n in range(32):
        if n < shift:
            x[n] = y[n]
        else:
            x[n] = y[n] ^ (mask[n] & x[n-shift])

    if direction == 'left':
        x.reverse()

    return bit_list_to_int(x)

def untemper(y: int) -> int:
    """
    Reverses the temper part of the Mersenne Twister.
    """
    (w, n, m, r) = (32, 624, 397, 31)
    a = 0x9908B0DF
    (u, d) = (11, 0xFFFFFFFF)
    (s, b) = (7, 0x9D2C5680)
    (t, c) = (15, 0xEFC60000)
    l = 18
    f = 1812433253

    xx = y
    xx = invert_shift_mask_xor(xx, direction='right', shift=l)
    xx = invert_shift_mask_xor(xx, direction='left', shift=t, mask=c)
    xx = invert_shift_mask_xor(xx, direction='left', shift=s, mask=b)
    xx = invert_shift_mask_xor(xx, direction='right', shift=u, mask=d)

    return xx
    
def get_cloned_rng(original_rng: callable) -> callable:
    """Taps the given rng for 624 outputs, untempers each of them to recreate the state of the generator,
    and splices that state into a new "cloned" instance of the MT19937 generator.
    """
    mt = []

    # Recreate the state mt of original_rng.
    for i in range(MT19937.N):
        mt.append(untemper(original_rng.extract_number()))

    # Create a new generator and set it to have the same state.
    cloned_rng = MT19937(0)
    cloned_rng.mt = mt

    return cloned_rng
    
def main():

	seed = random.randint(0, 2**32 - 1)
	rng = MT19937(seed)
	cloned_rng = get_cloned_rng(rng)

	# Check that the two PRNGs produce the same output.
	for i in range(99):
		if rng.extract_number() != cloned_rng.extract_number():
		    assert rng.extract_number() == cloned_rng.extract_number()
		    
	return
	
if __name__=="__main__":
	main()
