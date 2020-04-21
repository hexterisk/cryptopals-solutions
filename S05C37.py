# Imports
import os
import web
import json
import time
import random
import hashlib
from lib import *

# Web server
urls = (
    '/hello', 'Hello',
    '/init', 'Initiate',
    '/verify', 'Verify'
)

app = web.application(urls, globals())

# Client and server agree on these values beforehand

# Generated using "openssl dhparam -text 1024".
N = int("008c5f8a80af99a7db03599f8dae8fb2f75b52501ef54a827b8a1a586f14dfb20d6b5e2ff878b9ad6bca0bb9"
        "18d30431fca1770760aa48be455cf5b949f3b86aa85a2573769e6c598f8d902cc1a0971a92e55b6e04c4d07e"
        "01ac1fa9bdefd1f04f95f197b000486c43917568ff58fafbffe12bde0c7e8f019fa1cb2b8e1bcb1f33", 16)
g = 2
k = 3
I = "hextersik@hexterisk.com"
P = "hexterisk"
K = None
salt = str(random.randint(0, 2**32 - 1))
# since we can't save x, xH
v = pow(g, int(hashlib.sha256(salt.encode()+P.encode()).hexdigest(), 16), N)

class Hello:        
    
    def GET(self):
        params = web.input()
        name = params.name
        if not name:
            name = 'World'
            
        string = "Hello, " + name + "!"
        return {"name" : string}
    
class Verify:

    def GET(self):
        
        global K, salt
        
        params = web.input()
        hmac_received = params.hmac
        
        HMAC_obj = HMAC(K, hashlib.sha256)
        hmac = HMAC_obj.compute(salt.encode())
        
        if hmac == hmac_received:
            return "OK"

class Initiate:
    
    def GET(self):
        
        global K, salt
        
        params = web.input()
        I = params.I
        A = int(params.A)
        
        b = random.randint(0, N - 1)
        B = k*v + pow(g, b, N)
        
        uH = hashlib.sha256(str(A).encode()+str(B).encode()).hexdigest()
        u = int(uH, 16)
        # S will be zero since modulo N will be zero for 0 and multiples of N
        S = pow(A * pow(v, u, N), b, N)
        K = hashlib.sha256(str(S).encode()).digest()
        
        return {"salt":salt, "B":B}
        
def implement_SRP_zero() -> bool:
    """
    Implement SRP(Secure Remote Password) for proposed "A" values.
    """
    
    # This loop goes over proposed values for "A" by the question.
    for A in [0, N, N*2]:
        a = random.randint(0, N - 1)

        response = app.request("/init?I=" + I + "&A=" + str(A))
        response_dict = json.loads(response.data.decode("utf-8").replace("'",'"'))
        salt = response_dict["salt"]
        B = int(response_dict["B"])

        uH = hashlib.sha256(str(A).encode()+str(B).encode()).hexdigest()
        u = int(uH, 16)

        xH = hashlib.sha256(salt.encode()+P.encode()).hexdigest()
        x = int(xH, 16)

        # S = modular_pow((B - k * modular_pow(g, x, N)), (a + u * x), N)
        # We put S=0 because we know it's going to be zero on the server side
        S = 0
        K = hashlib.sha256(str(S).encode()).digest()

        HMAC_obj = HMAC(K, hashlib.sha256)
        hmac = HMAC_obj.compute(salt.encode())

        response = app.request("/verify?hmac=" + hmac)
        assert response.data.decode("utf-8") == "OK"
        print("> Verification successful.")
        return True
        
def main():

	assert implement_SRP_zero()
	
	return
	
if __name__ == "__main__":
	main()
