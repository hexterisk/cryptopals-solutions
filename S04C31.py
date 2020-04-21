# Imports
import os
import web
import json
import time
import hashlib
from lib import *

class HMAC:
    """
    Computes the HMAC for the hash function given at the time of initialisation.
    This implementation resembles the one of the Wikipedia pseudo-code.
    """
    
    def __init__(self: object, random_key: bytes, hash_func: callable):
        self.hash_func = hash_func
        self.block_size = hash_func().block_size

        if len(random_key) > self.block_size:
            self.key = hash_func(random_key).digest()
        elif len(random_key) < self.block_size:
            self.key = random_key + b'\x00' * (self.block_size-len(random_key))

    def compute(self: object, message: bytes) -> bytes:
        o_key_pad = xor_bytes(self.key, b'\x5c' * self.block_size)
        i_key_pad = xor_bytes(self.key, b'\x36' * self.block_size)
        
        inner_hash = self.hash_func(i_key_pad + message).digest()
        
        return self.hash_func(o_key_pad + inner_hash).hexdigest()

# Web Server
urls = (
    '/hello', 'Hello',
    '/test', 'Hash'
)

app = web.application(urls, globals())

HMAC_obj = HMAC(b"YELLOW_SUBMARINE", hashlib.sha1)

class Hello:        
    
    def GET(self):
        params = web.input()
        name = params.name
        if not name:
            name = 'World'
            
        string = "Hello, " + name + "!"
        return {"name" : string}

class Hash:
    
    def _insecure_compare(self, hash1, hash2, delay):
        for b1, b2 in zip(hash1, hash2):
            if b1 != b2:
                return False
            time.sleep(delay)
        return True
    
    def GET(self):
        global HMAC_obj
        params = web.input()
        file = params.file
        signature = params.signature
        delay = params.delay
        
        hmac = HMAC_obj.compute(file.encode())
        if self._insecure_compare(hmac.encode(), signature.encode(), float(delay)):
            return web.HTTPError(200)
        else:
            return web.HTTPError(500)
            
def main():

	# Given
	delay = 0.05
	
	signature = ""
	filename = "foo"
	# We go for twice the size because hexadecimal byte is 2 digits long.
	for _ in range(hashlib.sha1().digest_size * 2):
		
		times = []
		# This loop goes over all 16 hexadecimal bytes.
		for i in range(16):
		    start = time.time()
		    response = app.request("/test?delay=" + str(delay) + "&file=" + filename + "&signature=" + signature + hex(i)[-1])
		    finish = time.time()
		    times.append(finish - start)
		signature += hex(times.index(max(times)))[-1]
		print("> Discovered signature:", signature)

	response = app.request("/test?delay=" + str(delay) + "&file=" + filename + "&signature=" + signature + hex(i)[-1])
	if response.status == 200:
		print("> Brute force successful.\n> Signature:", signature)
	else:
		print("Brute force failed.")
		
		return
		
if __name__=="__main__":
	main()
