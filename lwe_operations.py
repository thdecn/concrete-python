import numpy as np
from lwe_encrypt import *

#----Functions for Homomorphic Addition and Subtraction-------------------------
def nb_bit_from_variance_99(var, torus_bits):
    """Computes the number of bits affected by normal distributed noise with a Variance var.
        Takes into account the number of bits of the integers.
    Args:
        var: Variance of the normal distribution.
        torus_bits: from q=2^torus_bits.
    Returns:
        Number of affected bits.
    """
    # Compute std_dev
    sigma = np.sqrt(var)
    # Constant to get 99% of the normal distribution
    z = 3.0
    tmp = np.float64(torus_bits) + np.float64(np.log2(sigma * z))
    if tmp < 0.0:
        # Means no bits are affected by the noise in the integer representation (discrete space)
        nr_bit = 0
    else:
        nr_bit = np.ceil(tmp)

    return nr_bit

def update_precision_from_variance(var, enc, q):
    """After an homomorphic operation, update an encoder using the new variance.
    Args:
        var: new variance.
        enc: Encoder to be updated [min, delta, nb_bit_precision, nb_bit_padding, round].
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Returns the number of bits of precision affected by the noise.
    Errors:
        NoNoiseInCiphertext: If there is no noise in the ciphertext.
    """
    torus_bits = np.int64(np.log2(q))
    # Check output noise
    nb_noise_bits = nb_bit_from_variance_99(var, torus_bits)

    new_precision = np.uint64(0)
    # Check if there is noise in the ciphertext
    if (nb_noise_bits == 0):
        print("NoNoiseInCiphertext")
    elif ( nb_noise_bits + enc[2] + enc[3] > torus_bits ):
        # Compute the number of bits which can be overwritten by the noise
        nb_bit_overlap = nb_noise_bits + enc[2] + enc[3] - torus_bits
        # If the overlap is at least as big as the precision, there is no more message
        new_precision = np.maximum(enc[2] - nb_bit_overlap, 0)

    return new_precision

def add_constant_static_encoder(ct1, enc1, message, p, q):
    """Add a small message to an LWE ciphertext.
        The encoding does not change but the body of the ciphertext does.
    Args:
        ct1: Ciphertext.
        enc1: Corresponding array of Encoder parameters (min, delta, precision_bits, padding_bits).
        message: Message to be added to ct1.
        p: plaintext modulus 2^precision_bits.
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Ciphertext ct1.
        Corresponding Encoder enc1.
    Erros:
        MessageTooBigError: If the message is bigger than the ct interval.
    """
    # Error if one message is not in [-delta,delta]
    if (np.abs(message) > enc1[1]):
        print("MessageTooBigError")

    max = (float(p-1)/float(p)*float(enc1[1])) + 0.0
    ct1[-1] = (ct1[-1] + encoder(message, 0.0, max, np.uint64(enc1[3]), p, q)) % q

    return ct1, enc1

def add_constant_dynamic_encoder(ct1, enc1, message, q):
    """Add a message to an LWE ciphertext and shifts the interval with a distance equal to the message.
         Does not change the body or the masks of the ciphertext.
    Args:
        ct1: Ciphertext.
        enc1: Corresponding array of Encoder parameters (min, delta, precision_bits, padding_bits).
        message: Message to be added to ct1.
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Ciphertext ct1.
        Corresponding Encoder enc.
    """

    enc = np.zeros(4)
    enc[0] = enc1[0] + message
    enc[1] = enc1[1]
    enc[2] = enc1[2]
    enc[3] = enc1[3]

    return ct1, enc

def add_with_new_min(ct1, var1, enc1, ct2, var2, enc2, new_min, p, q):
    """Compute an homomorphic addition between two LWE ciphertexts.
    Args:
        ct1, ct2: Ciphertexts to be added.
        var1, var2: Corresponding variances.
        enc1, enc2: Corresponding encoder values [min, delta, nb_bit_precision, nb_bit_padding].
        new_min: New minimum interval for the output encoder.
        p: plaintext modulus 2^precision_bits.
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Ciphertext ct3.
        Corresponding Variance var3.
        Corresponding Encoder enc3.
    Erros:
        DimensionError - If the ciphertexts have incompatible dimensions.
        DeltaError - If the ciphertexts have incompatible deltas.
        PaddingError - If the ciphertexts have incompatible paddings.
    """
    # Check dimensions
    if (len(ct1) != len(ct2)):
        print("DimensionError")

    # Add the two ciphertexts together
    ct3 = (ct1 + ct2) % q

    # Error if the deltas are not identical as well as the paddings
    # Checks
    tmp = np.abs(enc1[1] - enc2[1]) / np.maximum(enc1[1], enc2[1])
    limit1 = enc1[1] / pow(2.0, -40)
    limit2 = enc2[1] / pow(2.0, -40)
    if ( not (tmp < limit1 and tmp < limit2) ):
        print("DeltaError")
    if (enc1[3] != enc2[3]):
        print("PaddingError")

    # Update the variances and the Encoder
    # Compute the new variance
    var3 = var1 + var2

    # Encoder
    enc3 = np.zeros(4)
    enc3[0] = new_min
    enc3[1] = enc1[1]
    enc3[2] = enc1[2]
    enc3[3] = enc1[3]

    # Correction related to the addition
    max = enc3[0] + (enc3[1] * (p - 1.0) / p)
    ct3[-1] = (ct3[-1] + encoder(enc1[0] + enc2[0], enc3[0], max, np.uint64(enc3[3]), p, q) ) % q

    # Update the encoder precision based on the variance
    # __TODO__ enc3[2] = update_precision_from_variance(var3, enc3, q)

    return ct3, var3, enc3

def add_centered(ct1, var1, enc1, ct2, var2, enc2, p, q):
    """Compute an homomorphic addition between two LWE ciphertexts.
        The center of the output Encoder is the sum of the two centers of the input Encoders.
    Args:
        ct1, ct2: Ciphertexts to be added.
        var1, var2: Corresponding variances.
        enc1, enc2: Corresponding encoder values [min, delta, nb_bit_precision, nb_bit_padding].
        p: plaintext modulus 2^precision_bits.
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Ciphertext ct3.
        Corresponding Variance var3.
        Corresponding Encoder enc3.
    Erros:
        DimensionError - If the ciphertexts have incompatible dimensions.
        DeltaError - If the ciphertexts have incompatible deltas.
    """
    # Checks
    if (len(ct1) != len(ct2)):
        print("DimensionError")

    # Error if the deltas are not identical
    # Checks
    tmp = np.abs(enc1[1] - enc2[1]) / np.maximum(enc1[1], enc2[1])
    limit1 = enc1[1] / pow(2.0, -40)
    limit2 = enc2[1] / pow(2.0, -40)
    if ( not (tmp < limit1 and tmp < limit2) ):
        print("DeltaError")

    # Add the two ciphertexts together
    ct3 = (ct1 + ct2) % q

    # Correction for the addition
    enc3 = np.zeros(4)
    enc3[0] = 0.0
    enc3[1] = enc1[1]
    enc3[2] = enc1[2]
    enc3[3] = enc1[3]
    max = enc3[0] + (enc3[1] * (p - 1.0) / p)
    correction = encoder(enc1[1]/2.0, enc3[0], max, np.uint64(enc3[3]), p, q)
    ct3[-1] = np.uint64((np.int64(ct3[-1]) - np.int64(correction)) % q)

    # Update the variances and the Encoder
    # Compute the new variance
    var3 = var1 + var2

    # Encoder
    enc3[0] = enc1[0] + enc2[0] + enc1[1] / 2.0

    # Update the encoder precision based on the variance
    # __TODO__ enc3[2] = update_precision_from_variance(var3, enc3, q)

    return ct3, var3, enc3

def lwe_addition(ct1, var1, enc1, ct2, var2, enc2, exact, q):
    """Compute an addition between two LWE ciphertexts by eating one bit of padding.
        Corresponds to "add_with_padding_{exact}" from the Rust implementation.
    Args:
        ct1, ct2: Ciphertexts to be added.
        enc1, enc2: Corresponding encoder values [min, delta, nb_bit_precision, nb_bit_padding].
        var1, var2: Corresponding variances.
        exact: exact=1 ? (message bits increase max(nb1,nb2) + 1) :
                            (message bits stay the same min(nb1,nb2)).
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Ciphertext ct3.
        Corresponding Variance var3.
        Corresponding Encoder enc3.
    Errors:
        DeltaError: The encoders have incompatible deltas.
        PaddingError: The encoders have incompatible paddings.
        NotEnoughPaddingError: Number of padding bits is zero.
        DimensionError: The ciphertexts have incompatible dimensions.
    """
    # Checks
    tmp = np.abs(enc1[1] - enc2[1]) / np.maximum(enc1[1], enc2[1])
    limit1 = enc1[1] / pow(2.0, -40)
    limit2 = enc2[1] / pow(2.0, -40)
    if ( not (tmp < limit1 and tmp < limit2) ):
        print("DeltaError")
    if (enc1[3] != enc2[3]):
        print("PaddingError")
    if (len(ct1) != len(ct2)):
        print("DimensionError")
    # At least one bit of padding needed
    if (enc1[3] == 0):
        print("NotEnoughPaddingError")

    # Add ciphertexts together
    ct3 = np.uint64(np.zeros(len(ct1)))
    for j in range(len(ct1)):
        ct3[j] = (ct1[j] + ct2[j]) % q

    # Update the variances and the Encoder
    # Compute the new variance
    var3 = var1 + var2

    # Compute the new encoder
    enc3 = np.zeros(len(enc1))
    enc3[0] = enc1[0] + enc2[0]
    enc3[1] = enc1[1] * 2.0
    if (exact == 0):
        enc3[2] = np.minimum(enc1[2], enc2[2])
    else:
        enc3[2] = np.maximum(enc1[2], enc2[2]) + 1
    enc3[3] = enc1[3] - 1

    # Update the encoder precision based on the variance
    # __TODO__ enc3[2] = update_precision_from_variance(var3, enc3, q)

    return ct3, var3, enc3

def lwe_subtraction(ct1, var1, enc1, ct2, var2, enc2, exact, q):
    """Compute a subtraction between two LWE ciphertexts by eating one bit of padding.
        Corresponds to "sub_with_padding_{exact}" from the Rust implementation.
    Args:
        ct1, ct2: Ciphertexts to be subtracted.
        enc1, enc2: Corresponding encoder values [min, delta, nb_bit_precision, nb_bit_padding].
        var1, var2: Corresponding variances.
        exact: exact=1 ? (message bits increase max(nb1,nb2) + 1) :
                            (message bits stay the same min(nb1,nb2)).
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Ciphertext ct3.
        Corresponding Variance var3.
        Corresponding Encoder enc3.
    Errors:
        DeltaError: The encoders have incompatible deltas.
        PaddingError: The encoders have incompatible paddings.
        NotEnoughPaddingError: Number of padding bits is zero.
        DimensionError: The ciphertexts have incompatible dimensions.
    """
    # Checks
    tmp = np.abs(enc1[1] - enc2[1]) / np.maximum(enc1[1], enc2[1])
    limit1 = enc1[1] / pow(2.0, -40)
    limit2 = enc2[1] / pow(2.0, -40)
    if ( not (tmp < limit1 and tmp < limit2) ):
        print("DeltaError")
    if (enc1[3] != enc2[3]):
        print("PaddingError")
    if (len(ct1) != len(ct2)):
        print("DimensionError")
    # At least one bit of padding needed
    if (enc1[3] == 0):
        print("NotEnoughPaddingError")

    # Subtract ciphertexts
    ct3 = np.uint64(np.zeros(len(ct1)))
    for j in range(len(ct1)):
        ct3[j] = np.uint64((np.int64(ct1[j]) - np.int64(ct2[j])) % q)

    # Correction related to the subtraction
    correction = 1 << np.int(np.log2(q) - enc1[3])
    ct3[-1] = (ct3[-1] + np.uint64(correction)) % q

    # Update the variances and the Encoder
    # Compute the new variance
    var3 = var1 + var2

    # Compute the new encoder
    enc3 = np.zeros(len(enc1))
    enc3[0] = enc1[0] - (enc2[0] + enc2[1])
    enc3[1] = enc1[1] * 2.0
    if (exact == 0):
        enc3[2] = np.minimum(enc1[2], enc2[2])
    else:
        enc3[2] = np.maximum(enc1[2], enc2[2]) + 1
    enc3[3] = enc1[3] - 1

    # Update the encoder precision based on the variance
    # __TODO__ enc3[2] = update_precision_from_variance(var3, enc3, q)

    return ct3, var3, enc3

#===============================================================================

#----Functions for Homomorphic Multiplication with a Constant-------------------

def mul_constant_static_encoder(ct, var, enc, constant, p, q):
    """Multiply an LWE ciphertext with a small integer message.
        The encoding does not change, the body and mask do.
    Args:
        ct: Ciphertext.
        var: Corresponding variance.
        enc: Corresponding array of Encoder parameters (min, delta, precision_bits, padding_bits).
        constant: Integer constant for multiplication.
        p: plaintext modulus 2^precision_bits.
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Ciphertext ct_out.
        Corresponding Variance var_out.
        Corresponding Encoder enc_out.
    """
    # Multiplication
    ct_out = (ct * constant) % q

    # Compute and Apply correction to Body
    max = enc[0] + (enc[1] * (p - 1.0) / p)
    pt0 = encoder(0.0, enc[0], max, np.uint64(enc[3]), p, q)
    correction = (pt0 * (constant - 1)) % q
    ct_out[-1] = np.uint64( (np.int64(ct_out[-1]) - correction) % q )

    # Compute the absolute value of the message
    c_abs = np.uint64(np.abs(constant))
    # Estimate the new variance
    var_out = var * (c_abs * c_abs)
    # Copy Encoder
    enc_out = enc

    #if (c_abs != 0) :
        # Update the encoder precision based on the variance
        # __TODO__ enc_out[2] = update_precision_from_variance(var_out, enc_out, q)

    return ct_out, var_out, enc_out

def mul_constant_with_padding(ct, var, enc, constant, max_constant, nb_bit_padding, p, q):
    """Multiply an LWE ciphertext with a real constant.
        Change the encoding and the ciphertexts by consuming some bits of padding.
        The input encoding should contain zero in its interval.
        The output precision is the minimum between the input and the number of bits of padding consumed
    Args:
        ct: Ciphertext.
        var: Corresponding variance.
        enc: Corresponding array of Encoder parameters (min, delta, precision_bits, padding_bits).
        constant: Real constant for scaling ct.
        max_constant: A positive scaling factor for encoder, has to be greater than abs(constant).
        nb_bit_padding: Number of padding bits to be consumed.
        p: plaintext modulus 2^precision_bits.
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Ciphertext ct_out.
        Corresponding Variance var_out.
        Corresponding Encoder enc_out.
    Erros:
        ConstantMaximumError: If the constant is bigger than max_constant.
        ZeroInIntervalError: If zero is not in the interval described by the encoder.
        NotEnoughPaddingError: If there is not enough padding.
    """
    # Check that the constant is below the maximum
    if (constant > max_constant or constant < -max_constant):
        print("ConstantMaximumError")
    # Check that zero is in the interval
    if (enc[0] > 0.0 or (enc[0]+enc[1]) < 0.0 ):
        print("ZeroInIntervalError")
    # Check bits of paddings
    if (enc[3] < nb_bit_padding):
        print("NotEnoughPaddingError")

    # Absolute value of constant
    c_abs = np.abs(constant)
    # Discretize c_abs with regard to the number of bits of padding to use
    scal = np.int64(np.round(c_abs / max_constant * pow(2.0, nb_bit_padding)))

    # Encode 0 and subtract it from Body
    max = (float(p-1)/float(p)*float(enc[1])) + enc[0]
    tmp_sub = encoder(0.0, enc[0], max, np.uint64(enc[3]), p, q)
    ct[-1] = (ct[-1] - tmp_sub) % q

    # Scalar Multiplication
    ct = (ct * scal) % q

    # New Encoder
    new_o = enc[0] * max_constant
    new_max = (enc[0] + enc[1] - (enc[1] / pow(2.0, enc[2]))) * max_constant
    new_delta = new_max - new_o
    # Compute the discretization of c_abs
    discret_c_abs = float(scal) * pow(2.0, -nb_bit_padding) * max_constant
    # Compute the rounding error on c_abs
    rounding_error = np.abs(discret_c_abs - c_abs)
    # Get the ciphertext granularity
    granularity = enc[1] / pow(2.0, enc[2])
    # Compute the max of the ciphertext (based on the metadata of the encoder)
    max = np.maximum(np.abs(enc[0] + enc[1] - (enc[1] / pow(2.0, enc[2]))), np.abs(enc[0]))
    # Compute the new granularity
    new_granularity = 2.0 * np.abs(granularity * rounding_error / 2.0 + granularity / 2.0 * discret_c_abs + rounding_error * max)
    # Compute the new precision
    new_precision = np.minimum(np.floor(np.log2(new_delta / new_granularity)), enc[2])

    # Create the new encoder
    enc_out = np.zeros(4)
    enc_out[0] = new_o
    enc_out[1] = new_delta
    enc_out[2] = np.minimum(np.minimum(nb_bit_padding, enc[2]), new_precision)
    enc_out[3] = enc[3] - nb_bit_padding

    # Estimate the new variance
    var_out = var * (float(scal) * float(scal))

    #if (scal != 0):
        # Update the encoder precision based on the variance
        # __TODO__ enc_out[2] = update_precision_from_variance(var_out, enc_out, q)

    # Encode 0 with the new encoder
    max_out = (float(p-1)/float(p)*float(enc_out[1])) + enc_out[0]
    tmp_add = encoder(0.0, enc_out[0], max_out, np.uint64(enc_out[3]), p, q)
    ct[-1] = (ct[-1] + tmp_add) % q

    if (constant < 0.0):
        # Compute the opposite
        ct = np.uint64( (-np.int64(ct)) % q )
        # Add correction if there is some padding
        correction = np.int64(0)
        torus_bits = np.int64(np.log2(q))

        if (enc_out[3] > 0):
            correction = (1 << (torus_bits - np.int64(enc_out[3]))) - (1 << (torus_bits - np.int64(enc_out[3]) - np.int64(enc_out[2]))) % q
        else:
            correction = (correction - (1 << (torus_bits - np.int64(enc_out[3]) - np.int64(enc_out[2])))) % q

        ct[-1] = (ct[-1] + correction) % q

        # Change the encoder
        enc_out[0] = -(enc_out[0] + enc_out[1] - (enc_out[1] / pow(2.0, enc_out[2])))

    ct_out = ct
    return ct_out, var_out, enc_out

#===============================================================================

#----Functions for ... ---------------------------------------------------------
def opposite(ct, enc, q):
    """Compute the opposite of a ciphertext.
    Args:
        ct: Ciphertext.
        enc: array of Encoder parameters (min, delta, precision_bits, padding_bits).
        q: ciphertext modulus 2^torus_bits.
    Returns:
        Opposite of ct.
    """
    # Compute the opposite
    ct_out = np.uint64( (-np.int64(ct)) % q )

    # Add correction if there is some padding
    correction = np.int(0)
    torus_bits = np.int(np.log2(q))
    padding = np.int(enc[3])
    precision = np.int(enc[2])
    if (padding > 0):
        correction = (1 << (torus_bits - padding)) - (1 << (torus_bits - padding - precision))
    else:
        correction = (correction - (1 << (torus_bits - padding - precision))) % q
    ct_out[-1] = (ct_out[-1] + correction) % q

    # Change the encoder
    enc_out = np.zeros(4)
    old_max = enc[0] + enc[1] - (enc[1] / pow(2.0, enc[2]))
    enc_out[0] = -old_max
    enc_out[1] = enc[1]
    enc_out[2] = enc[2]
    enc_out[3] = enc[3]

    return ct_out, enc_out

#===============================================================================
