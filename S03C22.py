# Imports
import time
import random
from lib import *

def MT19937_timestamp_seed() -> (int, int):
    
    # Sleeps for a random time to generate a random seed.
    time.sleep(random.randint(40, 100))
    seed = int(time.time())
    
    # Initialises the object with the generated seed.
    mt_rng = MT19937(seed)
    
    # Sleep for a random time to throw off the attacker.
    time.sleep(random.randint(40, 100))
    return mt_rng.extract_number(), seed
    
def break_MT19937_seed(rng_function: callable) -> int:
    
    random_number, real_seed = rng_function()
    
    # Note current time to start backtracking by the millisecond.
    now = int(time.time())
    
    # Assuming nobody waits more than 220 seconds to get a random number
    before = now - 220
    # Brtue force with the value of seed between the set time frame.
    for seed in range(before, now):
        rng = MT19937(seed)
        number = rng.extract_number()
        if number == random_number:
            return seed
            
def main():
	print("Cloning successful. Number brute forced: ", break_MT19937_seed(MT19937_timestamp_seed))
	
	return
	
if __name__=="__main__":
	main()
