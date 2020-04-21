# Imports
import os
import struct
import binascii
from lib import *

key = os.urandom(16)

class MD4:
    """
    This implementation resembles the one of the Wikipedia pseudo-code.
    """
    
    buf = [0x00] * 64

    _F = lambda self, x, y, z: ((x & y) | (~x & z))
    _G = lambda self, x, y, z: ((x & y) | (x & z) | (y & z))
    _H = lambda self, x, y, z: (x ^ y ^ z)

    def __init__(self: object, message: bytes, ml=None, A=0x67452301, B=0xefcdab89, C=0x98badcfe, D=0x10325476):
        self.A, self.B, self.C, self.D = A, B, C, D

        if ml is None:
            ml = len(message) * 8
        length = struct.pack('<Q', ml)

        while len(message) > 64:
            self._handle(message[:64])
            message = message[64:]

        message += b'\x80'
        message += bytes((56 - len(message) % 64) % 64)
        message += length

        while len(message):
            self._handle(message[:64])
            message = message[64:]

    def _handle(self: object, chunk: bytes):
        X = list(struct.unpack('<' + 'I' * 16, chunk))
        A, B, C, D = self.A, self.B, self.C, self.D

        for i in range(16):
            k = i
            if i % 4 == 0:
                A = left_rotate((A + self._F(B, C, D) + X[k]) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._F(A, B, C) + X[k]) & 0xffffffff, 7)
            elif i % 4 == 2:
                C = left_rotate((C + self._F(D, A, B) + X[k]) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = left_rotate((B + self._F(C, D, A) + X[k]) & 0xffffffff, 19)

        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            if i % 4 == 0:
                A = left_rotate((A + self._G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, 5)
            elif i % 4 == 2:
                C = left_rotate((C + self._G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, 9)
            elif i % 4 == 3:
                B = left_rotate((B + self._G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, 13)

        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                A = left_rotate((A + self._H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, 9)
            elif i % 4 == 2:
                C = left_rotate((C + self._H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = left_rotate((B + self._H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, 15)

        self.A = (self.A + A) & 0xffffffff
        self.B = (self.B + B) & 0xffffffff
        self.C = (self.C + C) & 0xffffffff
        self.D = (self.D + D) & 0xffffffff

    def digest(self: object) -> bytes:
        return struct.pack('<4I', self.A, self.B, self.C, self.D)

    def hex_digest(self: object) -> bytes:
        return binascii.hexlify(self.digest()).decode()
        
def md_pad(message: bytes) -> bytes:
    """
    Pads the given message the same way the pre-processing of the MD4 algorithm does.
    """
    ml = len(message) * 8

    message += b'\x80'
    message += bytes((56 - len(message) % 64) % 64)
    message += struct.pack('<Q', ml)

    return message
    
def validate(modified_message: bytes, new_md: bytes) -> bool:
    """
    Verifies if the padding is correct.
    """
    if MD4(modified_message).hex_digest() == new_md:
        return True
    return False
    
def md4_length_extension_attack(message: bytes, original_md: bytes, payload: bytes) -> bytes:
    """
    Performs the length extension attack on an MD4.
    """
    for key_length in range(20):
        h = struct.unpack('<4I', bytes.fromhex(original_md))
        modified_message = md_pad(b'A'*key_length + message)[key_length:] + payload
        new_md = MD4(payload, (len(modified_message) + key_length)*8, h[0], h[1], h[2], h[3]).hex_digest()
        if validate(modified_message, new_md):
            print("> Length extension attack successful.")
            return modified_message, new_md
            break
            
def main():

	# Given
	message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	payload = b";admin=true"
	
	original_md = MD4(message.encode()).hex_digest()
	modified_message, new_md = md4_length_extension_attack(message.encode(), original_md, payload)
	
	assert payload in modified_message
	
	return
	
if __name__=="__main__":
	main()
