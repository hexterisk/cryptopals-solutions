# Imports
import hashlib
from lib import *

def nonce_recovery_from_repeated_nonce(message_dicts: dict, q: int) -> int:
    """
    Finds the signature pair using the same value for k from the given strings.
    """

    # Find indices of signatures with matching r.
    found = False
    r1, s1, s2, m1, m2 = 0, 0, 0, 0, 0
    for i in range(len(message_dicts)):
        for j in range(len(message_dicts[i:])):
            if message_dicts[i]["r"] == message_dicts[j]["r"]:
                m1 = message_dicts[i]["m"]
                m2 = message_dicts[j]["m"]
                if m1 == m2:
                    continue
                found = True
                r1 = message_dicts[i]["r"]
                s1 = message_dicts[i]["s"]
                s2 = message_dicts[j]["s"]                
                break
        if found:
            break
    # Calculate the value of k once matching r has been found.
    k = (((m1 - m2) % q) * mod_inverse((s1 - s2) % q, q)) % q
    return DSA_x_from_k(k, q, r1, s1, m1)
    
def main():

	# Given
	data = open("44.txt", "r").read()
	q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
	y = int("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
		"5519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a"
		"6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16)
	target = "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
	
	data_list = data.split('\n')
	message_dicts = []
	for i in range(0, len(data_list)-4, 4):
		message_dicts.append({"msg":data_list[i][5:], "s":int(data_list[i + 1][3:]), "r":int(data_list[i + 2][3:]), "m":int(data_list[i + 3][3:], 16)})
	
	recovered_x = nonce_recovery_from_repeated_nonce(message_dicts, q)
	assert(hashlib.sha1(hex(recovered_x)[2:].encode()).hexdigest() == target)

	return

if __name__ == "__main__":
	main()
