import numpy as np

#----Functions for encoding and decoding----------------------------------------
def encoder(message, min, max, padding_bits, p, q):
    """Encoding a message into a fixed-precision plaintexts.
    Args:
        message: Message to be encoded.
        min: minimum value.
        max: maximum value. Interval is [min, max[
        padding_bits: nr of padding bits to be used in the plaintext.
        p: plaintext modulus 2^precision_bits.
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Plaintext pt.
    """
    margin = (max - min) / (p - 1.0)
    delta = max - min + margin
    pt = np.uint64(np.round( ((message - min) / delta) * q ))
    pt = pt >> padding_bits
    return pt

def decoder(plaintext, min, max, padding_bits, p, q):
    """Decoding a plaintext back into a message.
    Args:
        plaintext: Plaintext to be decoded.
        min: minimum value.
        max: maximum value.
        padding_bits: nr of padding bits to be used in the plaintext.
        p: plaintext modulus 2^precision_bits.
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Message m.
    """
    margin = (max - min) / (p - 1.0)
    delta = max - min + margin
    shifted_pt = plaintext << padding_bits
    m = ((float(shifted_pt) / float(q)) * delta) + min
    return m

#===============================================================================

#----Functions for Key Generation, Encryption and Decryption--------------------
def keygen(k):
    """Generate a Secret key s.
    Args:
        k: size of Secret key vector.
    Returns:
        Secret key s.
    """
    return np.random.randint(0, 2, k)

def encrypt(pt, secret_key, std_dev, q):
    """Encrypt a Plaintext pt with Secret Key secret_key and noise standard deviation std_dev.
    Args:
        pt: Plaintext to be encrypted.
        secret_key: Secret Key.
        std_dev: standard deviation for the error normal distribution.
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Ciphertext ct.
    """
    # Generate Masks and Error
    a = np.uint64(np.random.randint(0, q, len(secret_key)))
    e = np.random.normal(0.0, std_dev, 1)
    e = np.uint64(np.round(e * q) % q)

    # Dot product of Masks and Secret Key
    s_a = np.uint64(np.dot(secret_key, a) % q)
    # Create Ciphertext
    ct = np.uint64(np.zeros(len(secret_key)+1))
    # Masks
    ct[0:-1] = a
    # Body
    ct[-1] = (s_a + e + pt) % q
    return ct

def encode_encrypt(message, secret_key, enc, std_dev, q):
    """Encode a Message and encrypt its Plaintext.
    Args:
        message: Message to be encoded and encrypted.
        secret_key: Array of Secret Key bits.
        enc: array of Encoder parameters (min, delta, precision_bits, padding_bits).
        std_dev: standard deviation for the error normal distribution.
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Ciphertext ct.
        Variance var of the noise in the ciphertext.
        Encoder enc of the ciphertext.
    """
    # Unpack Encoder
    min = enc[0]
    delta = enc[1]
    precision_bits = np.uint(enc[2])
    padding_bits = np.uint(enc[3])
    p = pow(2, precision_bits)
    max = min + (delta * (p - 1.0) / p)

    # Compute Plaintext
    plaintext = encoder(message, min, max, padding_bits, p, q)
    # Compute Ciphertext
    ct = encrypt(plaintext, secret_key, std_dev, q)
    # Compute the variance
    var = pow(std_dev, 2)

    return ct, var, enc

def decrypt(ct, secret_key, p, q):
    """Decrypt a Ciphertext ct with Secret Key secret_key.
    Args:
        ct: Ciphertext to be decrypted.
        secret_key: Secret Key.
        p: plaintext modulus 2^precision_bits+padding_bits.
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Plaintext pt.
    """
    a = ct[0:-1]
    b = ct[-1]
    s_a = np.uint64(np.dot(secret_key, a) % q)
    pt = np.uint64(np.round( (np.int64(b) - np.int64(s_a)) % q))
    return upper(pt, q, p)

def upper(x, q, p):
    """Upper Function.
    Args:
        x: input Element
        q: ciphertext Modulus q=2^torus_bits
        p: cleartext Modulus p=2^(padding_bits + precision_bits)
    Returns:
        Upper_q,p(x).
    """
    return np.uint64( (float(q)/float(p) * np.round(float(p)/float(q) * float(x))) % q )

def decrypt_decode(ciphertext, secret_key, enc, q):
    """Decrypt a Ciphertext ct and decode its plaintext.
    Args:
        ct: Ciphertext to be decrypted.
        secret_key: Secret Key.
        enc: array of Encoder parameters (min, delta, precision_bits, padding_bits).
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Plaintext pt.
    """
    # Unpack Encoder
    min = enc[0]
    delta = enc[1]
    precision_bits = np.uint(enc[2])
    padding_bits = np.uint(enc[3])
    p = pow(2, precision_bits)
    max = min + (delta * (p - 1.0) / p)
    # Decrypt
    plaintext = decrypt(ciphertext, secret_key, pow(2, precision_bits + padding_bits), q)
    # Decode
    message = decoder(plaintext, min, max, padding_bits, p, q)
    return message

#===============================================================================
