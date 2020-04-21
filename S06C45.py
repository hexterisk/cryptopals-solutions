# Imports
from lib import *

class DSA_flawed(DSA):
    """
    Extends the DSA public key encryption / decryption.
    Allows r = 0, hence flawed.
    """
    
    def generate_signature(self: object, message: bytes) -> (int, int):
        while True:
            k = random.randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q                
            s = (mod_inverse(k, self.q) * (self.H(message) + self.x * r)) % self.q
            if s != 0:
                break
        return (r, s)
        
def DSA_parameter_tampering() -> bool:
    """
    Parameter tampering for a flawed DSA.
    Exploits the vulnerability where value of r is not checked for zero.
    """

    dsa = DSA_flawed(g = DSA.DEFAULT_P + 1)
    message = "g = (p + 1) DSA"
    signature = dsa.generate_signature(message.encode())
    print("> Message:", message)
    print("> Signature generated for g = (p + 1).\nr:", signature[0], "\ns:", signature[1])
    check = dsa.verify_signature(signature[0], signature[1], message.encode())
    if check:
        print("> Signature successfully verified for original message.")
    
    z = random.randint(1, 100)
    y = dsa.key_distribution()
    forged_r = pow(y, z, DSA_flawed.DEFAULT_P) % DSA_flawed.DEFAULT_Q
    forged_s = (forged_r * mod_inverse(z, dsa.DEFAULT_Q)) % dsa.DEFAULT_Q
    
    message1 = "Hello, world"
    message2 = "Goodbye, world"
    
    print("> Values from forged signature:\nr:", forged_r, "\ns:", forged_s)
    
    print("> Message 1:", message1)
    if dsa.verify_signature(forged_r, forged_s, message1.encode()):
        print("> Signature successfully verified for message 1.")
    print("> Message 2:", message2)
    if dsa.verify_signature(forged_r, forged_s, message2.encode()):
        print("> Signature successfully verified for message 2.")
        return True
        
def main():

	assert(DSA_parameter_tampering())
	
	return

if __name__ == "__main__":
	main()
