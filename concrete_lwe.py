
""" __TODO__ Solve the max - margin - granularity issue or raise [Q] to Zama
    # The granularity is the smallest increment between two consecutive values
    ##granularity = (max - min) / p
    ##delta = max - min + granularity

    #    /// Computes the smallest real number that this encoding can handle
    #    pub fn get_granularity(&self) -> f64 {
    #        self.delta / f64::powi(2., self.nb_bit_precision as i32)
    #    }
    #    pub fn get_max(&self) -> f64 {
    #        self.o + self.delta - self.get_granularity()
    #    }

    -> in encoder
    let margin: f64 = (max - min) / (f64::powi(2., nb_bit_precision as i32) - 1.);

    Ok(Encoder {
                o: min,
                delta: max - min + margin,
                nb_bit_precision: nb_bit_precision,
                nb_bit_padding: nb_bit_padding,
    })
"""

# __TODO__
## [ ] Test-main in different file -> error should be in granularity!
## [ ] fix casting
## [ ] Final Check, then add to GitHub
## [Delay] Display functions, Visualise nb_bit_overlap
## [Delay] Strip Noise Function? Or Disable Noise?
## [Delay]Check functions and guards
"""
Schedule Week 2
    [ ] Sunday - Publish Encoder, Encrypt, Decrypt, Decode + README.md from Notion [4h]
    [X] Debug using display functions - immideiately shows its usefulness
    [ ] Monday - Opposite code + Mult int Code  [4h]
    [ ] Tuesday - Opposite code + Mult int Document [4h]
    [ ] Wednesday -  Add Cst & Add1 & Add2 Code [4h]
    [ ] Thursday - Add Cst & Add1 & Add2 Documentation [4h]
"""
# Not Implemented yet
## * new_rounding_context: (constructor with encoder-> round = true)
## * new_centered constructor: (constructor with the provided interval as [center-radius,center+radius[)
## * copy constructor & zero constructor
## * new_square_divided_by_four // for bootstrapping
## * update_precision_from_variance
# __TODO__ solve the margin vs granularity issue

# [Q] Why is it called encode_outside_interval_operators?? outside of the interval?

import numpy as np
import matplotlib.pyplot as plt

#--------Functions for encoding and decoding------------------------------------
def encoder(message, min, max, padding_bits, p, q):
    """Encoding a message into a fixed-precision plaintexts.
    Args:
        message: Message to be encoded.
        min: minimum value.
        max: maximum value. Interval is [min, mac[
        padding_bits: nr of padding bits to be used in the plaintext.
        p: plaintext modulus 2^precision_bits.
        q: Ciphertext modulus 2^torus_bits.
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
        p: plaintext modulus 2^precision_bits+__TODO__padding_bits?.
        q: Ciphertext modulus 2^torus_bits.
    Returns:
        Message m.
    """
    margin = (max - min) / (p - 1.0)
    delta = max - min + margin
    m = plaintext << padding_bits

    # __TODO__ what's with this?  is this the Upper function?
    # Round if round is set to false and if in the security margin
    precision = np.int64(np.log2(p))
    torus_bits = np.int64(np.log2(q))
    starting_value_security_margin = ((1 << (precision + 1)) - 1) << (torus_bits - precision)
    if (m > starting_value_security_margin):
        print("Rarely happens")
    #    m = round_to_closest_multiple(m, self.nb_bit_precision, 1)
    # __END__TODO__

    m = ((float(m) / float(q)) * delta) + min
    return m

#===============================================================================

#--------Functions for Key Generation, Encryption and Decryption----------------
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
        q: Ciphertext modulus 2^torus_bits.
    Returns:
        Ciphertext ct.
    """
    # Generate Masks and Error
    a = np.uint64(np.random.randint(0, q, len(secret_key)))
    e = np.random.normal(0.0, std_dev, 1)
    e = np.uint64(np.round(e * q)) % q

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
        secret_key: Array of Secret Key bits.
        message: Message as an u64.
        enc: array of Encoder parameters.
    Returns:
        Ciphertext ct.
        Variance var of the noise in the ciphertact.
        Encoder of the ciphertext
    """
    # Unpack Encoder
    min = enc[0]
    delta = enc[1]
    precision_bits = np.uint(enc[2])
    padding_bits = np.uint(enc[3])
    max = min + delta - (delta / pow(2, precision_bits)) #__TODO__
    p = pow(2, precision_bits)

    # Compute Plaintext
    plaintext = encoder(message, min, max, padding_bits, p, q)
    display_pt(plaintext, padding_bits, precision_bits)
    # Compute Ciphertext
    ct = encrypt(plaintext, secret_key, std_dev, q)
    display_pt(plaintext, padding_bits, precision_bits)

    # Compute the variance
    var = pow(std_dev, 2)
    """ __TODO__
    # Notify if a problem occured
    nb_bit_overlap = update_precision_from_variance(var, enc, q)
    if (nb_bit_overlap > 0):
        print("{ Loss of precision during encrypt }: {", nb_bit_overlap, "} bit(s) with {", precision_bits, "} bit(s) of message originally. Consider increasing the dimension the reduce the amount of noise needed.")
    """
    return ct, var, enc

def decrypt(ct, secret_key, p, q):
    """Decrypt the ciphertext, meaning compute the phase and directly decode the output as if the encoder was in a rounding context
    __TODO__
    """
    a = ct[0:-1]
    b = ct[-1]
    s_a = np.uint64(np.dot(secret_key, a) % q)
    pt = np.uint64(np.round( (np.int64(b) - np.int64(s_a)) % q))
    return upper(pt, q, p)

def upper(x, q, p):
    """Upper Function.
    Args:
        x: Input Element
        q: Ciphertext Modulus q=2^torus_bits
        p: Cleartext Modulus p=2^(padding_bits + precision_bits)
    Returns:
        Upper_q,p(x).
    """
    return np.uint64( (float(q)/float(p) * np.round(float(p)/float(q) * float(x))) % q )

def decrypt_decode(ciphertext, secret_key, enc, q):
    """Decrypt the ciphertext, meaning compute the phase and directly decode the output.
    __TODO__
    """
    # Unpack Encoder
    min = enc[0]
    delta = enc[1]
    precision_bits = np.uint(enc[2])
    padding_bits = np.uint(enc[3])
    max = min + delta - (delta / pow(2, precision_bits))
    p = pow(2, precision_bits)
    # Decrypt
    plaintext = decrypt(ciphertext, secret_key, pow(2, precision_bits + padding_bits), q)
    display_pt(plaintext, padding_bits, precision_bits)
    # Decode
    message = decoder(plaintext, min, max, padding_bits, p, q)
    return message

def display_pt(plaintext, padding, precision):
    bin_pt = bin(plaintext)
    bin_pt = bin_pt[2:-1] # Strip "0b"
    bin_pt = (32-len(bin_pt))*'0' + bin_pt
    print(bin_pt[0:padding] + " " + bin_pt[padding:padding+precision] + " " + bin_pt[padding+precision:-1])

def display(plaintext, enc):
    # Unpack Encoder
    min = enc[0]
    delta = enc[1]
    precision_bits = np.uint(enc[2])
    padding_bits = np.uint(enc[3])
    max = min + delta - (delta / pow(2, precision_bits))
    p = pow(2, precision_bits)
    granularity = (max - min) / p

    print("Plaintext: ", plaintext, "Min: ", min, "delta: ", delta, "precision: ", precision_bits, "padding", padding_bits, "granularity", granularity)

#===============================================================================

# [ ] __TODO__ Check dimensions, outputs, comments, casting and possible simplification wrt extra functions.
# [ ] Torus_bit as macro, sheesh

def get_bit(binary_key, n, q):
    """Returns the n-th bit (a boolean) of a binary key viewed as a key for a LWE sample.
    Args:
     * `binary_key` - a Torus slice representing the binary key
     * `n` - the index of the wanted bit
    Results:
     * the n-th bit of k as a boolean
    """
    torus_bits = np.uint64(np.log2(q))

    # Finds the right case of the slice
    i = np.uint64(n / torus_bits)
    cell = np.uint64(binary_key[i])
    # Finds the right bit in the Torus element
    j = np.uint64(n % torus_bits)
    bit = (cell >> np.uint64( (torus_bits - 1) - j )) & np.uint64(1)
    # Return a boolean
    return bit == 1

def set_val_at_level_l(val, base_log, level_l, q):
    """Returns a Torus element with a some bits a the right place according to the base_log and level decomposition.
    Args:
     * val - a Torus element containing on its LSB some bit we want to move at a precise place
     * base_log - decomposition log2 base
     * level_l - the desired level
    Returns:
     * a torus element build as desired
    """
    torus_bits = np.uint64(np.log2(q))

    res = np.uint64(0)
    shift = np.uint64(torus_bits - (base_log * (level_l + 1)))
    res += np.uint64(np.uint64(val) << shift)
    return res

def ksk_keygen(sk_before, sk_after, base_log, level, std_dev, q):
    """Generate an LWE key switching key ksk.
    Args:
     * sk_before - an LWE secret key (input for the key switch)
     * sk_after - an LWE secret key (output for the key switch)
     * base_log - the log2 of the decomposition base
     * level - the number of levels of the decomposition
    Returns:
     * Key Switching Key ksk
    """
    # Dimensions are of the form len(key)-1
    # n * kN * level + n * level = (kN * level) * (n + 1)
    ksk_size = ( len(sk_before) * len(sk_after) * level ) + ( len(sk_before) * level )

    # Initializse ksk_ciphertexts to contain the Toric RGSW ciphertexts
    ksk_ciphertexts = np.uint64(np.zeros(ksk_size))

    # Fill Key Switching Key
    chunk_size = (len(sk_after) + 1) * level

    # Loop over the output
    for i in range(0, len(ksk_ciphertexts), chunk_size):
        # Fetch the i-th of the before key bit
        # i/chunk_size = 0/chunk_size, 1800/chunk_size, 3600/chunk_size, ... = 0, 1, 2, ...
        bit = get_bit(sk_before, i/chunk_size, q)

        messages = np.uint64(np.zeros(level))
        if bit:
            for j in range(level):
                messages[j] = set_val_at_level_l(1, base_log, j, q)

        # Encrypts the i-th of the before key bit
        lwe_size = len(sk_after) + 1
        for j in range(level):
            ksk_ciphertexts[i+(j*lwe_size):i+((j+1)*lwe_size)] = encrypt(messages[j], sk_after, std_dev, q)
    # Compute variance
    var = pow(std_dev, 2)
    return ksk_ciphertexts, base_log, level, var

def npe_key_switch(dimension_before, l_ks, base_log, var_ks, var_input, q):
    """Return the variance of the keyswitch on an LWE sample given a set of parameters.
    Args:
     * dimension_before - size of the input LWE mask.
     * l_ks - number of level max for the torus decomposition.
     * base_log - number of bits for the base B (B=2^base_log).
     * var_ks - variance of the keyswitching key.
     * var_input - variance of the input LWE.
    Results:
     * This function compute the noise of the keyswitch without functional evaluation.
    """
    torus_bits = np.int64(np.log2(q))
    q_square = float(pow(2., 2 * torus_bits))
    res_1 = float(dimension_before) * (1.0 / 24.0 * pow(2.0, -2 * (base_log * l_ks)) + 1.0 / (48.0 * q_square))
    res_2 = float(dimension_before) * float(l_ks) * (pow(2.0, 2 * base_log) / 12.0 + 1.0 / 6.0) * var_ks
    res = var_input + res_1 + res_2
    return res

def keyswitch(ciphertext_before, ksk, base_log, level, var_ksk, var_input, enc, dimension_before, dimension_after, q):
    """Compute a key switching operation on every ciphertext from the LWE struct self.
    Args:
     * `ksk` - the key switching key
    Results:
     * a LWE struct
    """
    # Allocation for the result
    ciphertext_after = np.uint64(np.zeros(dimension_after + 1)) # __TODO__ + 1 is added myself for the body? or is it all masks?
    # Key Switch
    ciphertext_after = key_switch(ciphertext_after, ciphertext_before, ksk, base_log, level, dimension_before, dimension_after, q)

    # Deal with encoders, noise and new precision
    # Calls the NPE to find out the amount of noise after KS
    var = npe_key_switch(dimension_before, level, base_log, var_ksk, var_input, q)

    # Update the precision
    """
    let nb_bit_overlap: usize = res.encoder.update_precision_from_variance(res.variance)?;

    # Notification of a problem
    if nb_bit_overlap > 0 {
        println!(
            "{}: {} bit(s) lost, with {} bit(s) of message originally",
            "Loss of precision during key switch".red().bold(),
            nb_bit_overlap,
            self.encoder.nb_bit_precision
        );
    }
    """
    return ciphertext_after, var, enc

def round_to_closest_multiple(x, base_log, level, q):
    """Rounds a torus element to its closest torus element with only lv_tot * log_b MSB that can be different from zero
         Example with binary representations:
         round_to_closest_multiple(1100100...0,2,2) -> 11010...0
         we will only keep 2*2 = 4 MSB
         so we can put a dot where the rounding happens, which is after the 4th MSB: 1100.1 is rounded to 1101
    Args:
     * x - element of the Torus to be rounded
     * base_log - number of bits for the base B (B=2^base_log)
     * level - number of blocks of the gadget matrix
    Results:
     * the rounded Torus element
    """
    torus_bits = np.int64(np.log2(q))
    # Number of bits to throw out
    shift = np.uint64(torus_bits - level * base_log)
    # Get the first bit (MSB) to be thrown out
    mask = np.uint64(1) << np.uint64(shift - 1)
    b = np.uint64(x & mask) >> np.uint64(shift - 1)
    # Do the truncation by shifting the MSB into LSB
    res = np.uint64(x) >> shift
    # Do the rounding
    res += b
    # Put back the MSB where they belong
    res = res << shift
    return res


def torus_small_sign_decompose(val, base_log, level, q):
    """Computes a signed decomposition of a Torus element.
        The base is B = 2^base_log
        We end up with coefficients in [-B/2, B/2[
    Args:
     * `res` - a tensor of signed integers (output)
     * `val` - the Torus element to be decomposed
     * `base_log` - number of bits for the base B (B=2^base_log)
    """
    torus_bits = np.int64(np.log2(q))
    carry = 0
    tmp = 0
    previous_carry = 0
    # Create a temporary variable that will contain each signed decomposition in the loop
    decomp = np.zeros(level)

    # 000...000011...11 : there are base_log ones in the LSB, it represents a block
    block_bit_mask = (1 << base_log) - 1
    # 000...000010...00 : the one is in the MSB of the block
    msb_block_mask = 1 << (base_log - 1)
    # Compute the decomposition from LSB to MSB (because of the carry)
    # for i in (0..res.len()).rev() {
    for i in reversed(range(len(decomp))):
        previous_carry = carry
        tmp = (val >> np.uint64(torus_bits - base_log * (i + 1))) & np.uint64(block_bit_mask)
        carry = tmp & np.uint64(msb_block_mask)
        tmp = (tmp + previous_carry) % q
        # 0000...0001000 or 0000...0000000
        carry = carry | (np.uint64(tmp) & np.uint64(msb_block_mask))
        # res[i] = (tmp as i32) - b;
        decomp[i] = (tmp - (carry << np.uint64(1)))
        ## 000...0001 or 000...0000
        carry = carry >> np.uint64(base_log - 1)
    return decomp

def sub_scalar_mul(res, t_in, n, q):
    """Subtract to res the multiplication of t_in by a scalar n.
    Description:
     * res <- res - t_in * n
    Args:
     * `t_in` - Torus slice
     * `n` - integer (u32 or u64)
    """
    for i in range(len(t_in)):
        res[i] = (res[i] - (t_in[i] * n) % q) % q
    return res

def key_switch(ct_res, ct_in, ksk, base_log, level, dimension_before, dimension_after, q):
    """Keyswitch several LWE ciphertexts encrypted under the same key.
     * `ct_res` - Torus slice containing the output LWEs (output)
     * `ct_in` - Torus slice containing the input LWEs
     * `ksk` - Torus slice containing the keyswitching key
     * `base_log` - number of bits for the base B (B=2^base_log)
     * `level` - number of blocks of the gadget matrix
     * `dimension_before` - size of the LWE masks before key switching (typical value: n=1024)
     * `dimension_after` - size of the LWE masks after key switching (typical value: n=630)
    Results:
     * ct_res: ciphertext after
    """
    lwe_size_before = dimension_before + 1
    lwe_size_after = dimension_after + 1

    # For each ciphertext, call mono_key_switch
    """
    for loop 1: for (block_res, block_in) in ct_res.chunks_mut(lwe_size_after).zip(ct_in.chunks(lwe_size_before)):
        block_res[dimension_after] = block_in[dimension_before]
    """
    # Copy Bodies? __TODO__
    ct_res[dimension_after] = ct_in[dimension_before]

    # Compute chunk's size according to level and dimensions parameters
    chunk_size = level * (dimension_after + 1)

    # Loop over the coefficients in the LWE
    # a_i will represent the i-th value of the input mask
    # Block represent blocks of the KSK
    """
    for (block, ai) in ksk.chunks(chunk_size).zip(block_in.iter()):
    """
    for j in range(len(ct_in)):
        block = ksk[j*chunk_size:(j+1)*chunk_size]
        # (len(ksk)/chunk_size) = len(ct_in)
        a_i = ct_in[j]
        a_i_rounded = round_to_closest_multiple(a_i, base_log, level, q)
        decomp = torus_small_sign_decompose(a_i_rounded, base_log, level, q)
        # Loop over the number of levels
        # d is the i-th element of the signed decomposition
        #for (block_i, d) in block.chunks(dimension_after + 1).zip(decomp.iter()):
        for i in range(len(decomp)):
            block_i = block[i*(dimension_after + 1):(i+1)*(dimension_after + 1)]
            ct_res = sub_scalar_mul(ct_res, block_i, decomp[i], q)
    """
    End for loop 1
    """
    #print(decomp) # __TODO__ Test with reconstruction
    return ct_res

#===============================================================================
#===============================================================================
#===============================================================================

# [ ] __TODO__

def bsk_keygen(sk_input, sk_output, polynomial_size, base_log, level):
    """Create a valid bootstrapping key.
    Args:
     * `sk_before` - an LWE secret key (input for the bootstrap)
     * `sk_after` - an RLWE secret key (output for the bootstrap)
     * polynomial_size - polynomial size of sk_output
     * `base_log` - the log2 of the decomposition base
     * `level` - the number of levels of the decomposition
    Results:
     * an LWEBSK
    """
    # Allocation for the bootstrapping key
    # __NOTE__ Contains CTours values (c64) -> complex numbers
    bootstrapping_key_size = len(sk_output) * (len(sk_output) + 1) * polynomial_size * level * len(sk_input)
            + polynomial_size * level * (len(sk_output) + 1) * len(sk_input)

    trgsw_ciphertexts = np.zeros(bootstrapping_key_size)

    """
    crypto::RGSW::create_fourier_bootstrapping_key(
        &mut trgsw_ciphertexts,
        base_log,
        level,
        sk_output.dimension,
        sk_output.polynomial_size,
        sk_output.std_dev,
        &sk_input.val,
        &sk_output.val,
    );

    LWEBSK {
        ciphertexts: trgsw_ciphertexts,
        variance: f64::powi(sk_output.std_dev, 2),
        dimension: sk_output.dimension,
        polynomial_size: sk_output.polynomial_size,
        base_log: base_log,
        level: level,
    }
    """

def encrypt_gsw(pt, s, l, beta, std1, q, poly_mod):
    k = len(s)
    Z_matrix = np.zeros([(k+1)*l, k+1])
    for j in range((k+1)*l):
        Z_matrix[j,:] = encrypt(0, s, std1, q, poly_mod)

    g_exponents = np.log2(q) - np.array(range(beta, (l+1)*beta, beta))
    g = pow(2, g_exponents)

    G_T = np.zeros([(k+1)*l, k+1])
    for j in range(0, k+1):
        G_T[j*l:j*l+l, j] = np.transpose(g)

    ct = np.int64((Z_matrix + pt*G_T) % q)
    return ct


def sample_extraction():
    return 

def test_encode_encrypt_x_decrypt():
    # Random settings
    min = -0.0
    max = 256.0
    precision = 12
    padding = 2
    torus_bit = 32
    std_dev = pow(2,-9)
    p = pow(2, precision)
    q = pow(2, torus_bit)
    margin = (max - min)/(p-1)
    delta = max - min + margin
    granularity = (max - min) / p
    k = 4

    # Generate Secret Key
    secret_key = keygen(k)
    enc = np.array([min, delta, precision, padding])

    i = 0
    for j in range(100):
        # Generate Random Message
        message = min + (np.random.rand()*(max-min))
        message_noencrypt = decoder(encoder(message, min, max, np.uint64(padding), p, q), min, max, np.uint64(padding), p, q)
        # Encode & Encrypt
        ciphertext, var, enc = encode_encrypt(message, secret_key, enc, std_dev, q)
        # Decrypt & Decode
        message_star = decrypt_decode(ciphertext, secret_key, enc, q)
        # Test if error is within bounds
        print(message, "  ->  ", message_star)
        print(message_noencrypt, "  ->  ", message_star)
        if (np.abs((message_star - message)) >= granularity):
            i += 1
            print("Granularity Exceeded: ", np.abs((message_star - message)), " < ", granularity)
            # the decoded message will not always match exactly the original message, but rather the closest value that the encoder can represent.
    print(i)

    print("==================")
    print("=======KSK========")
    """
    dimension_before = 1024
    dimension_after = 600
    sk_before = keygen(dimension_before)
    sk_after = keygen(dimension_after)
    base_log = 4
    level = 8
    std_dev = pow(2,-9)
    var_input = pow(std_dev, 2)
    q = pow(2, 32)
    ksk, base_log, level, var_ksk = ksk_keygen(sk_before, sk_after, base_log, level, std_dev, q)

    message = min + (np.random.rand()*(max-min))
    enc = np.array([min, delta, precision, padding])
    ciphertext_before, var, enc = encode_encrypt(message, sk_before, enc, std_dev, q)
    message_star = decrypt_decode(ciphertext_before, sk_before, enc, q)
    print(message, "  ->  ", message_star)

    enc = np.array([min, delta, precision, padding])
    ciphertext_after, var, enc = keyswitch(ciphertext_before, ksk, base_log, level, var_ksk, var_input, enc, dimension_before, dimension_after, q)
    message_star = decrypt_decode(ciphertext_after, sk_after, enc, q)
    print(message, "  ->  ", message_star)
    """
    print("==================")
    print("=======BSK========")
    base_log = 4
    level = 3
    bsk_keygen(sk_input, sk_output, polynomial_size, base_log, level)


def main():
    test_encode_encrypt_x_decrypt()

if __name__ == "__main__":
    main()
