# Imports
import re
import hashlib
from lib import *

ASN1_SHA1 = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"

class RSA_Digital_Signature(RSA):
    """
    Extends the RSA class coded before with the sign / verify functions.
    """
	
    global ASN1_SHA1

    def generate_signature(self: object, message: bytes) -> bytes:
        digest = hashlib.sha1(message).digest()
        block = b'\x00\x01' + (b'\xff' * (128 - len(digest) - 3 - 15)) + b'\x00' + ASN1_SHA1 + digest
        signature = self.decrypt(int.from_bytes(block, "big"), "big")
        return signature

    def verify_signature(self: object, message: bytes, signature: bytes) -> bool:
        cipher = self.encrypt(signature, "big")
        block = b'\x00' + cipher.to_bytes((cipher.bit_length() + 7) // 8, "big")
        r = re.compile(b'\x00\x01\xff+?\x00.{15}(.{20})', re.DOTALL)
        m = r.match(block)
        if not m:
            return False
        digest = m.group(1)
        return digest == hashlib.sha1(message).digest()
        
def forge_signature(message: bytes) -> bytes:
    """
    Forges the SHA1 signature of the message
    """
    
    global ASN1_SHA1
	
    digest = hashlib.sha1(message).digest()
    block = b'\x00\x01\xff\x00' +  ASN1_SHA1 + digest + (b'\x00' * (128 - len(digest) - 4 - 15))
    block_int = int.from_bytes(block, "big")
    sig = floorRoot(block_int, 3) + 1
    return sig.to_bytes((sig.bit_length() + 7) // 8, "big")
    
def main():
	
	# Given
	message = "hi mom"
		 
	rsa = RSA_Digital_Signature(1024)
	forged_signature = forge_signature(message.encode())
	if not rsa.verify_signature(message.encode(), forged_signature):
		raise Exception(message + b" has invalid signature " + forged_signature)
	else:
		print("> Signature verified for message:", message)
		
	return
	
if __name__ == "__main__":
	main()
