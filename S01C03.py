# Imports
from itertools import zip_longest
    
def single_byte_xor_letters(ciphertext: bytes) -> dict:
    """
    Performs xor between every possible key uptil 256 and returns the key that gives the most ascii characters.
    """
    
    ascii_text_chars = list(range(97, 122)) + [32]
    best_candidate = None
    
    for i in range(2**8): # for every possible key
        
        # converting the key from a number to a byte
        candidate_key = i.to_bytes(1, "big")
        keystream = candidate_key*len(ciphertext)
        
        candidate_message = bytes([x^y for (x, y) in zip(ciphertext, keystream)])
        nb_letters = sum([ x in ascii_text_chars for x in candidate_message])
        
        # if the obtained message has more letters than any other candidate before
        if best_candidate == None or nb_letters > best_candidate["nb_letters"]:
            # store the current key and message as our best candidate so far
            best_candidate = {"message": candidate_message.decode("utf-8"), "nb_letters": nb_letters, "key": candidate_key}
    
    return best_candidate
    
def calculate_score(text: str) -> float:
    """
    Calculates score of the given text based on a frequency chart of english alphabets.
    """
    
    # Block for frequency analysis
    frequency_chart = {
        'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 
        'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23,
        'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15,
        'X': 0.15, 'Q': 0.10, 'Z': 0.07, ' ': 35
    }
    
    score = 0.0
    for letter in text.upper():
        score += frequency_chart.get(letter, 0)
    return score

def single_byte_xor_score(ciphertext: bytes) -> dict:
    max_score = 0
    key = ''
    plaintext = ""
    
    for testkey in range(256):
        testtext = ""
        for letter in ciphertext:
            testtext += chr(letter ^ testkey)
        
        cur_score = calculate_score(testtext)
        if cur_score > max_score:
            max_score = cur_score
            key = chr(testkey)
            plaintext = testtext
            
    return {"score" : max_score, "key" : key, "message" : plaintext}

def main():

	# Given
	hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	
	byte_string = bytes.fromhex(hex_string)
	print("Using scoring technique...\n", single_byte_xor_score(byte_string)['message'])
	print("Using ASCII counting technique...\n", single_byte_xor_letters(byte_string)['message'])
	
	return

if __name__ == "__main__":
	main()
