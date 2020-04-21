#Imports
from lib import *

def main():

	# Given
	given_string = "ICE ICE BABY\x04\x04\x04\x04"
	target_string = "ICE ICE BABY"
	
	assert(target_string.encode() == PKCS7_unpad(given_string.encode()))
	
	return
	
if __name__=="__main__":
	main()

