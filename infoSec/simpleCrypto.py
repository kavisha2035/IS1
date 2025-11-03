import random
from Crypto.Cipher import AES
import os

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= 1
        if is_prime(n):
            return n

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    return x % phi

def generate_keypair(key_size=64):
    p = generate_prime(key_size // 2)
    q = generate_prime(key_size // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = generate_prime(key_size // 4)
    while e < phi:
        if extended_gcd(e, phi)[0] == 1:
            break
        e += 2
    
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def generate_aes_key(key_size=16):
    return os.urandom(key_size)  # Using os.urandom for better randomness

def simple_pad(data: bytes, block_size: int) -> bytes:
    """Simple padding: append the number of padding bytes to reach block size"""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def simple_unpad(data: bytes) -> bytes:
    """Remove the padding by reading the last byte which indicates padding length"""
    padding_length = data[-1]
    return data[:-padding_length]

def aes_encrypt(plaintext: str, key: bytes) -> bytes:
    try:
        # Generate a random IV
        iv = os.urandom(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Convert string to bytes and pad
        data = plaintext.encode('utf-8')
        padded_data = simple_pad(data, AES.block_size)
        
        # Encrypt
        ciphertext = cipher.encrypt(padded_data)
        
        # Return IV + ciphertext
        return iv + ciphertext
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def aes_decrypt(ciphertext: bytes, key: bytes) -> str:
    try:
        # Extract IV and ciphertext
        iv = ciphertext[:AES.block_size]
        ct = ciphertext[AES.block_size:]
        
        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ct)
        
        # Remove padding and convert to string
        plaintext = simple_unpad(padded_plaintext)
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")