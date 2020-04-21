# Imports
import os
import web
import json
import time
import hashlib
from lib import *

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
	delay = 0.005
	
	signature = ""
	filename = "foo"
	for _ in range(hashlib.sha1().digest_size * 2):
	# We go for twice the size because hexadecimal byte is 2 digits long.
		times = []
		# This loop goes over all 16 hexadecimal bytes.
		for i in range(16):
		    runtime = 0
		    # Introduced more rounds so the time difference is prominent
		    for _ in range(20):
		        start = time.time()
		        response = app.request("/test?delay=" + str(delay) + "&file=" + filename + "&signature=" + signature + hex(i)[-1])
		        finish = time.time()
		        runtime += finish - start
		    times.append(runtime)
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
