# Imports
import math
import struct
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime

# Init

from IPython import display

_HTML_INFO_STYLE = ( 'border:1px solid #c3e6cb;'
   'padding:.75rem 3rem;'
   'border-radius:.5rem;'
   'font-weight:bold;'
   'text-align: center;'
)

def test(condition):
    if condition:
        html = display.HTML(
            '<div style="' +
            _HTML_INFO_STYLE +
            'background-color:#d4edda;'
            'color:#155724;'
            'border-color:#c3e6cb;'
            '">Completed</div>')
    else:
        html = display.HTML(
            '<div style="' +
            _HTML_INFO_STYLE +
            'background-color:#f8d7da;'
            'color:#721c24;'
            'border-color:#f5c6cb;'
            '">Error</div>')

    display.display(html)

# Challenge 2

def xor_bytes(enc1: bytes, enc2: bytes) -> bytes:
    """
    xor_bytes computes the xor of two byte strings and returns the final value.
    """
    cipher = b"".join([bytes(b1^b2 for b1, b2 in zip(enc1, enc2))])
    return cipher
    
    
# Challenge 3

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
    
# Challenge 5

def repeated_xor(text: bytes, key: bytes) -> bytes:
    """
    Performs xor between given text and key. If the length is unequal, key repeats.
    """
    quotient, remainder = divmod(len(text), len(key))
    return bytes([x ^ y for x, y in zip(text, bytes(key * quotient + key[:remainder]))])
    
# Challenge 7

def AES_ECB_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts a ciphertext encrypted with AES ECB Mode.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)
    
# Challenge 8

def detect_AES_ECB(ciphertext: bytes) -> int:
    """
    Detect if the AES ECB encryption mode was used for creating the given ciphertexts.
    Returns the maximum number of repititions occuring for any particular block.
    """
    blocks = [ciphertext[i:i+AES.block_size] for i in range(0, len(ciphertext), AES.block_size)]
    return len(blocks)-len(set(blocks))
    
# Challenge 9

def PKCS7_pad(plaintext: bytes, block_size: int) -> bytes:
    """
    Pad the given text upto the length of given block_size following PKCS7 norms.
    """
    if len(plaintext) == block_size:
        return plaintext
    pad = block_size - len(plaintext) % block_size
    plaintext += (pad.to_bytes(1,"big"))*pad
    return plaintext
    
# Challenge 10

def PKCS7_padded(text: bytes) -> bool:
    """
    Checks if the given text is padded according to the PKCS7 norms.
    """
    padding = text[-text[-1]:]
    
    # Check that all the bytes in the range indicated by the padding are equal to the padding value itself.
    return all(padding[b] == len(padding) for b in range(0, len(padding)))
    
def PKCS7_unpad(paddedtext: bytes) -> bytes:
    """
    Unpads the given text if it's padded according to PKCS7 norms.
    """
    
    # Checks if the text is padded according to PKCS7 norms.
    if PKCS7_padded(paddedtext):
        # The last byte is a padding byte.
        pad_Length = paddedtext[len(paddedtext)-1]
        # Returns the text uptil last "pad" length bytes since pad byte value is the same as number of pad bytes required.
        return paddedtext[:-pad_Length]
    else:
        return paddedtext
        
def AES_CBC_decrypt(ciphertext: bytes, IV: bytes, key: bytes) -> bytes:
    """
    Decrypts a ciphertext encrypted with AES CBC Mode.
    AES ECB is the block cipher encryption of choice.
    Refer https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC) for the formulae.
    """
    previous = IV
    keysize = len(key)
    plaintext = b""
    cipher = ""
    
    for i in range(0, len(ciphertext), keysize):
        cipher = AES_ECB_decrypt(ciphertext[i:i+keysize], key)
        xor_list = [chr(b1 ^ b2) for b1, b2 in zip(cipher, previous)]
        plaintext += "".join(xor_list).encode()
        previous = ciphertext[i:i+keysize]
        
    return plaintext
    
# Challenge 11

def AES_ECB_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypts a plaintext with AES ECB Mode.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    text = PKCS7_pad(plaintext, len(key))
    return cipher.encrypt(PKCS7_pad(text, len(key)))
    
def AES_CBC_encrypt(plaintext: bytes, IV: bytes, key: bytes) -> bytes:
    """
    Encrypts a plaintext with AES CBC Mode.
    AES ECB is the block cipher encryption of choice.
    Refer https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC) for the formulae.
    """
    previous = IV
    keysize = len(key)
    ciphertext = b""
    xored = b""
    
    for i in range(0, len(plaintext), keysize):
        xor_list = [(b1 ^ b2).to_bytes(1, "big") for b1, b2 in zip(PKCS7_pad(plaintext[i:i+keysize], keysize), previous)]
        xored = b"".join(xor_list)
        cipher = AES_ECB_encrypt(xored, key)
        ciphertext += cipher
        previous = cipher
        
    return ciphertext
    
# Challenge 18

def CTR_keystream_generator(key: bytes, nonce: int) -> bytes:
    """
    Generates keystream based on given key and nonce.
    Uses AES ECB Mode to encrypt the nonce+counter block.
    """
    counter = 0
    # 8 byte because format says 64bit.
    nonce_bytes = nonce.to_bytes(8, "little")
    
    while True:
        counter_bytes = counter.to_bytes(8, "little")
        # Keep getting 16byte block from the encryption function.
        keystream_block = AES_ECB_encrypt(nonce_bytes + counter_bytes, key)
        yield from keystream_block
        counter += 1
        
def CTR(string: bytes, key: bytes, nonce: int) -> bytes:
    """
    Encrypts a plaintext with AES CTR Mode.
    """
    # Generate the keystream based on key and nonce.
    keystream = CTR_keystream_generator(key, nonce)
    
    if len(string) == 0:
        return b""
    else:
        return xor_bytes(string, keystream)
        
# Challenge 21

def get_lowest_bits(n: int, number_of_bits: int) -> int:
    """
    Returns the lowest "number_of_bits" bits of n.
    """
    mask = (1 << number_of_bits) - 1
    return n & mask

class MT19937:
    """
    This implementation resembles the one of the Wikipedia pseudo-code.
    """

    W, N, M, R = 32, 624, 397, 31
    A = 0x9908B0DF
    U, D = 11, 0xFFFFFFFF
    S, B = 7, 0x9D2C5680
    T, C = 15, 0xEFC60000
    L = 18
    F = 1812433253
    LOWER_MASK = (1 << R) - 1
    UPPER_MASK = get_lowest_bits(not LOWER_MASK, W)
    
    def __init__(self: object, seed: int):
        self.mt = []

        self.index = self.N
        self.mt.append(seed)
        for i in range(1, self.index):
            self.mt.append(get_lowest_bits(self.F * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.W - 2))) + i, self.W))
            
    def extract_number(self: object) -> int:
        """
        Extracts the new random number.
        """
        if self.index >= self.N:
            self.twist()

        y = self.mt[self.index]
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= (y >> self.L)

        self.index += 1
        return get_lowest_bits(y, self.W)

    def twist(self: object):
        """
        Performs the twisting part of the encryption.
        """
        for i in range(self.N):
            x = (self.mt[i] & self.UPPER_MASK) + (self.mt[(i + 1) % self.N] & self.LOWER_MASK)
            x_a = x >> 1
            if x % 2 != 0:
                x_a ^= self.A

            self.mt[i] = self.mt[(i + self.M) % self.N] ^ x_a

        self.index = 0
        
# Challenge 28

def left_rotate(value: int, shift: int) -> int:
    """
    Returns value left-rotated by shift bits. In other words, performs a circular shift to the left.
    """
    return ((value << shift) & 0xffffffff) | (value >> (32 - shift))


def sha1(message: bytes, ml=None, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0) -> bytes:
    """
    Returns a string containing the SHA1 hash of the input message. This is a pure python 3 SHA1
    implementation, written starting from the SHA1 pseudo-code on Wikipedia.
    The parameters ml, h0, ..., h5 are for the next challenge.
    """
    
    # Pre-processing:
    if ml is None:
        ml = len(message) * 8

    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    message += struct.pack('>Q', ml)

    # Process the message in successive 512-bit chunks:
    for i in range(0, len(message), 64):

        # Break chunk into sixteen 32-bit big-endian integers w[i]
        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack('>I', message[i + j * 4:i + j * 4 + 4])[0]

        # Extend the sixteen 32-bit integers into eighty 32-bit integers:
        for j in range(16, 80):
            w[j] = left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop
        for j in range(80):
            if j <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (d & (b | c))
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = left_rotate(a, 5) + f + e + k + w[j] & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value (big-endian) as a 160 bit number, hex formatted:
    return "%08x%08x%08x%08x%08x" % (h0, h1, h2, h3, h4)

def sha1_mac(key: bytes, message: bytes) -> bytes:
    return sha1(key + message)

# Challenge 31

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
        
# Challenge 33

class DiffieHellman():
    """
    Implements the Diffie-Helman key exchange. Each class is a party, which has his secret key (usually
    referred to as lowercase a or b) shares the public key (usually referred to as uppercase A or B) and can
    compute the shared secret key between itself and another party, given their public key, assuming that
    they are agreeing on the same p and g.
    """

    DEFAULT_G = 2
    DEFAULT_P = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b225'
                    '14a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f4'
                    '4c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc20'
                    '07cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed5'
                    '29077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)

    def __init__(self: object, g=DEFAULT_G, p=DEFAULT_P):
        self.g = g
        self.p = p
        self._secret_key = random.randint(0, p - 1)
        self.shared_key = None

    def gen_public_key(self: object) -> int:
        return pow(self.g, self._secret_key, self.p)

    def gen_shared_secret_key(self: object, other_party_public_key: int) -> int:
        if self.shared_key is None:
            self.shared_key = pow(other_party_public_key, self._secret_key, self.p)
        return self.shared_key
        
# Challenge 38

def mod_inverse(a: int, n: int) -> int: 
    """
    Computes the multiplicative inverse of a modulo n using the extended Euclidean algorithm.
    """
    
    t, r = 0, n
    new_t, new_r = 1, a

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise Exception("a is not invertible")
    if t < 0:
        t = t + n
    
    return t

class RSA:
    """
    Implementation of the RSA (Rivest–Shamir–Adleman) algorithm.
    """
    
    def __init__(self: object, keysize: int):
        e = 3
        et = 0
        n = 0

        while math.gcd(e, et) != 1:
            p, q = getPrime(keysize // 2), getPrime(keysize // 2)
            et = ((p - 1) * (q - 1)) // math.gcd(p - 1, q - 1)
            n = p * q

        d = mod_inverse(e, et)
        
        self.pub = (e, n)
        self.pvt = (d, n)

    def encrypt(self: object, message: bytes, byteorder="big") -> int:
        (e, n) = self.pub
        data = int.from_bytes(message, byteorder)
        
        if data < 0 or data >= n:
            raise ValueError(str(data) + ' out of range')
            
        return pow(data, e, n)
    
    def encryptnum(self: object, m: int) -> int:
        (e, n) = self.pub
        if m < 0 or m >= n:
            raise ValueError(str(m) + ' out of range')
        return pow(m, e, n)
    
    def decrypt(self: object, ciphertext: bytes, byteorder="big") -> bytes:
        (d, n) = self.pvt
        
        if ciphertext < 0 or ciphertext >= n:
            raise ValueError(str(ciphertext) + ' out of range')
        
        numeric_plain = pow(ciphertext, d, n)
        return numeric_plain.to_bytes((numeric_plain.bit_length() + 7) // 8, byteorder)
    
    def decryptnum(self: object, m: int) -> int:
        (d, n) = self.pvt
        if m < 0 or m >= n:
            raise ValueError(str(m) + ' out of range')
        return pow(m, d, n)
        
# Challenge 40

def floorRoot(n: int, s: int) -> int:
    """
    Finds the specified powered root of an integer and returns the resulting float's floor value.
    """
    
    b = n.bit_length()
    p = math.ceil(b/s)
    x = 2**p
    while x > 1:
        y = (((s - 1) * x) + (n // (x**(s-1)))) // s
        if y >= x:
            return x
        x = y
    return 1
    
# Challenge 43

class DSA:
    """
    Implements the DSA public key encryption / decryption.
    """
    
    DEFAULT_P = int("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76"
                    "c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232"
                    "c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
    DEFAULT_Q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    DEFAULT_G = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389"
                    "b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c88"
                    "7892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)
        
    def __init__(self: object, p = DEFAULT_P, q = DEFAULT_Q, g = DEFAULT_G):
        self.p = p
        self.q = q
        self.g = g
        self.x, self. y = self._per_user_key()
        self.pvt, self.pub = self.x, self.y
        
    def _per_user_key(self: object):
        x = random.randint(1, self.q - 1)
        y = pow(self.g, x, self.p)
        return x, y
    
    def H(self: object, message: bytes) -> bytes:
        return int(hashlib.sha1(message).hexdigest(), 16)
    
    def key_distribution(self: object) -> tuple:
        return self.pub
    
    def generate_signature(self: object, message: bytes) -> (int, int):
        
        while True:
            k = random.randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q
            if r == 0:
                continue
                
            s = (mod_inverse(k, self.q) * (self.H(message) + self.x * r)) % self.q
            if s != 0:
                break
        return (r, s)
    
    def verify_signature(self: object, r: int, s: int, message: bytes) -> bool:
        if r < 0 or r > self.q:
            return False
        if s < 0 or s > self.q:
            return False
        
        w = mod_inverse(s, self.q)
        u1 = (self.H(message) * w) % self.q
        u2 = (r * w) % self.q
        
        v1 = pow(self.g, u1, self.p)
        v2 = pow(self.y, u2, self.p)
        
        v = ((v1 * v2) % self.p) % self.q
        return v == r
    
# Challenge 47

def ceil(a: int, b: int) -> int:
    """
    Returns the ceil of division between two numbers.
    """
    return (a + b - 1) // b

def append_interval(M_narrow: list, lower_bound: int, upper_bound: int):
    """
    Append the passed bounds as an interval to the list.
    Write over the interval if tighter constraints are passed.
    Skip if it already exists.
    """
    
    # Check if there exist an interval which is overlapping with the lower_bound and
    # upper_bound of the new interval we want to append
    for i, (a, b) in enumerate(M_narrow):

        # If there is an overlap, then replace the boundaries of the overlapping
        # interval with the wider (or equal) boundaries of the new merged interval
        if not (b < lower_bound or a > upper_bound):
            new_a = min(lower_bound, a)
            new_b = max(upper_bound, b)
            M_narrow[i] = new_a, new_b
            return

    # If there was no interval overlapping with the one we want to add, add
    # the new interval as a standalone interval to the list
    M_narrow.append((lower_bound, upper_bound))
    return
    
# Challenge 44

def DSA_x_from_k(k: int, q: int, r: int, s: int, message_int: int) -> int:
    """
    Returns the value of x as calculated using other parameters.
    """
    return (((s * k) - message_int) * mod_inverse(r, q)) % q
