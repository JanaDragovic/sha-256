"""
SHA-256 implementacija prema zvaničnom NIST FIPS 180-4 standardu
Secure Hash Standard (SHS) - Federal Information Processing Standard Publication 180-4
"""

def rotr(x, n):
    """
    Rotacija udesno (ROTR - Rotate Right)
    (x >> n) XOR (x << w - n)
    """
    return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF

def shr(x, n):
    """
    Pomeranje udesno (SHR - Shift Right)
    x >> n
    """
    return x >> n

def ch(x, y, z):
    """
    Funkcija Ch (Choose)
    (x AND y) XOR (~x AND z)
    """
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    """
    Funkcija Maj (Majority)
    (x AND y) XOR (x AND z) XOR (y AND z)
    """
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0_256(x):
    """
    Funkcija Sigma0 
    """
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr (x, 22)

def sigma1_256(x):
    """
    Funkcija Sigma1
    """
    return rotr(x, 6) ^ rotr (x, 11) ^ rotr(x, 25) 

def sigma0_256_small(x):
    """
    Funkcija Sigma0 (mala)
    """
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def sigma1_256_small(x):
    """
    Funkcija Sigma1 (mala)
    """
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10) 

# Konstante za SHA-256
K_256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def padding(message_bytes):
    """
    Dodavanje padding-a poruci (Message Padding)
    """
    message_bit_length = len(message_bytes) * 8
    
    padded_message = message_bytes + b'\x80'  # Dodavanje '1' bita
    while (len(padded_message) * 8) % 512 != 448:
        padded_message += b'\x00'
    
    padded_message += message_bit_length.to_bytes(8, 'big')

    return padded_message

def parse_message(padded_message):
    """
    Parsiranje poruke u blokove
    """
    blocks = []

    for i in range(0, len(padded_message), 64):
        block = padded_message[i:i+64]
        words = []

        for j in range(0, 64, 4):
            word = int.from_bytes(block[j:j+4], 'big')
            words.append(word)
        blocks.append(words)

    return blocks

def sha256_hash_computation(message_blocks):
    """
    SHA-256 Hash računanje
    """
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    for block in message_blocks:
        w = block[:]
        for t in range(16, 64): 
            s0 = sigma0_256_small(w[t-15])
            s1 = sigma1_256_small(w[t-2])
            w.append((w[t-16] + s0 + w[t-7] + s1) & 0xFFFFFFFF)

        a, b, c, d, e, f, g, h_temp = h
        
        for t in range(64):
            s1 = sigma1_256(e)
            ch_val = ch(e, f, g)
            temp1 = (h_temp + s1 + ch_val + K_256[t] + w[t]) & 0xFFFFFFFF
            s0 = sigma0_256(a)
            maj_val = maj(a, b, c)
            temp2 = (s0 + maj_val) & 0xFFFFFFFF

            h_temp = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        for i in range(8):
            h[i] = (h[i] + [a, b, c, d, e, f, g, h_temp][i]) & 0xFFFFFFFF

        return h

def sha256(message):
    
    padded_message = padding(message)
    message_blocks = parse_message(padded_message)
    final_hash = sha256_hash_computation(message_blocks)
    return ''.join(f'{x:08x}' for x in final_hash)

# Test funkcije
def test_sha256():
    """
    Test funkcija sa primerima iz NIST standarda i za poznate test slučajeve
    """
    result1 = sha256("")
    expected1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    print(result1 == expected1)

    result2 = sha256("abc")
    expected2 = "ba7816bf8f01cfea414140de5dae2223b00361a39617829b8a0c5c85a5f5c5c"
    print(result2 == expected2)

if __name__ == "__main__":
    test_sha256()
    
   