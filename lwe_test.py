from lwe_encrypt import *
from lwe_operations import *

def generate_random_interval():
    coins = np.uint64(np.random.randint(0, pow(2, 32), 3))
    interval_type = coins[0] % 3
    interval_size = np.float64((coins[1] % (1000 * 1000))) / 1000.0
    interval_start = np.float64((coins[2] % (1000 * 1000))) / 1000.0
    if interval_type==0:
        # Negative interval
        min = -interval_start - interval_size
        max = -interval_start
    elif interval_type==1:
        # Positive interval
        min = interval_start
        max = interval_size + interval_start

    elif interval_type==2:
        # Zero in the interval
        tmp = np.float64((coins[2] % (1000 * 1000))) / (1000.0 * 1000.0) * interval_size
        min = -interval_size + tmp
        max = tmp
    else:
        min = 0.0
        max = 0.0

    return min, max

def generate_random_centered_interval():
    coins = np.uint64(np.random.randint(0, pow(2, 32), 2))
    interval_size = np.float64((coins[0] % (1000 * 1000))) / 1000.0

    # Zero in the interval
    tmp = np.float64((coins[1] % (1000 * 1000))) / (1000.0 * 1000.0) * interval_size
    min = -interval_size + tmp
    max = tmp
    return min, max

def test_encode_encrypt_x_decrypt():
    precision = 8
    padding = 4
    torus_bit = 32
    std_dev = pow(2,-19)
    p = pow(2, precision)
    q = pow(2, torus_bit)
    min, max = generate_random_interval()
    margin = (max - min)/(p-1)
    delta = max - min + margin
    granularity = (max - min) / p
    k = 4

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
        #print(message, "  ->  ", message_star)
        #print(message_noencrypt, "  ->  ", message_star)
        if (np.abs((message_noencrypt - message_star)) >= granularity):
            i += 1
            # The decoded message will not always match exactly the original message, but rather the closest value that the encoder can represent.
            print("Granularity Exceeded: ", np.abs((message_star - message)), " < ", granularity)
    if i==0:
        print("\x1b[6;30;42m" + "Number of times granilarity was exceeded after \n encode_encrypt x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")
    else:
        print("\x1b[0;30;41m" + "Number of times granilarity was exceeded after \n encode_encrypt x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")

def test_encode_encrypt_x_add_constant_static_encoder_x_decrypt():
    precision = 8
    padding = 4
    torus_bit = 32
    std_dev = pow(2,-19)
    p = pow(2, precision)
    q = pow(2, torus_bit)

    # Encoder
    min, max = generate_random_interval()
    min_encoder = min - 10.0
    max_encoder = max + 10.0
    margin_encoder = (max_encoder - min_encoder)/(p-1)
    delta_encoder = max_encoder - min_encoder + margin_encoder
    granularity = (max_encoder - min_encoder) / p
    k = 4
    enc = np.array([min_encoder, delta_encoder, precision, padding])

    # Secret Key
    secret_key = keygen(k)

    i = 0
    for j in range(100):
        # Generate Random Messages
        message1 = min + (np.random.rand()*(max-min))
        message2 = -10.0 + (np.random.rand()*(10.0-(-10.0)))

        # Encode & Encrypt
        ct1, var1, enc1 = encode_encrypt(message1, secret_key, enc, std_dev, q)

        # Compute the multiplication between ciphertext and message2
        ct_add, enc_add = add_constant_static_encoder(ct1, enc1, message2, p, q)

        # Decrypt & Decode
        message_star = decrypt_decode(ct_add, secret_key, enc_add, q)

        # Test if error is within bounds
        if (np.abs((message1 + message2) - message_star) >= granularity):
            i += 1
            print(message1, " + ", message2, " = ", message1 + message2, "  ->  ", message_star)
            print("Granularity Exceeded in Static Addition with a Constant: ", np.abs((message1 + message2) - message_star), " < ", granularity)
    if i==0:
        print("\x1b[6;30;42m" + "Number of times granilarity was exceeded after \n encode_encrypt x add_constant_static_encoder x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")
    else:
        print("\x1b[0;30;41m" + "Number of times granilarity was exceeded after \n encode_encrypt x add_constant_static_encoder x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")

def test_encode_encrypt_x_add_constant_dynamic_encoder_decrypt():
    precision = 8
    padding = 4
    torus_bit = 32
    std_dev = pow(2,-19)
    p = pow(2, precision)
    q = pow(2, torus_bit)

    # Encoder
    min1, max1 = generate_random_interval()
    min2, max2 = generate_random_interval()
    margin = (max1 - min1)/(p-1)
    delta = max1 - min1 + margin
    granularity = (max1 - min1) / p
    k = 4
    enc = np.array([min1, delta, precision, padding])

    # Secret Key
    secret_key = keygen(k)

    i = 0
    for j in range(100):
        # Generate Random Messages
        message1 = min1 + (np.random.rand()*(max1-min1))
        message2 = min2 + (np.random.rand()*(max2-min2))

        # Encode & Encrypt
        ct1, var1, enc1 = encode_encrypt(message1, secret_key, enc, std_dev, q)

        # Compute the multiplication between ciphertext and message2
        ct_add, enc_add = add_constant_dynamic_encoder(ct1, enc1, message2, q)

        # Decrypt & Decode
        message_star = decrypt_decode(ct_add, secret_key, enc_add, q)

        # Test if error is within bounds
        if (np.abs((message1 + message2) - message_star) >= granularity):
            i += 1
            print(message1, " + ", message2, " = ", message1 + message2, "  ->  ", message_star)
            print("Granularity Exceeded in Dynamic Addition with a Constant: ", np.abs((message1 + message2) - message_star), " < ", granularity)
    if i==0:
        print("\x1b[6;30;42m" + "Number of times granilarity was exceeded after \n encode_encrypt x add_constant_dynamic_encoder x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")
    else:
        print("\x1b[0;30;41m" + "Number of times granilarity was exceeded after \n encode_encrypt x add_constant_dynamic_encoder x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")

def test_encode_encrypt_x_add_with_new_min_x_decrypt():
    precision = 8
    padding = 4
    torus_bit = 32
    std_dev = pow(2,-19)
    p = pow(2, precision)
    q = pow(2, torus_bit)

    # Encoder
    min1, max1 = generate_random_interval()
    min2, max2 = generate_random_interval()
    max2 = min2 + max1 - min1
    margin1 = (max1 - min1)/(p-1)
    delta1 = max1 - min1 + margin1
    granularity = (max1 - min1) / p
    k = 4
    enc1 = np.array([min1, delta1, precision, padding])

    margin2 = (max2 - min2)/(p-1)
    delta2 = max2 - min2 + margin2
    enc2 = np.array([min2, delta1, precision, padding])

    # New min
    new_min = min1 + min2 + delta1/2.0

    # Secret Key
    secret_key = keygen(k)

    i = 0
    for j in range(100):
        # Generate Random Messages
        message1 = (min1 + delta1/2.0) + (np.random.rand()*(max1-(min1 + delta1/2.0)))
        message2 = min2 + (np.random.rand()*(delta1/2.0))

        # Encode & Encrypt
        ct1, var1, enc1 = encode_encrypt(message1, secret_key, enc1, std_dev, q)
        ct2, var2, enc2 = encode_encrypt(message2, secret_key, enc2, std_dev, q)

        # Compute the multiplication between ciphertext and message2
        ct_add, var_add, enc_add = add_with_new_min(ct1, var1, enc1, ct2, var2, enc2, new_min, p, q)

        # Decrypt & Decode
        message_star = decrypt_decode(ct_add, secret_key, enc_add, q)

        # Test if error is within bounds
        if (np.abs((message1 + message2) - message_star) >= granularity):
            i += 1
            print(message1, " + ", message2, " = ", message1 + message2, "  ->  ", message_star)
            print("Granularity Exceeded in Addition with New Min: ", np.abs((message1 + message2) - message_star), " < ", granularity)
    if i==0:
        print("\x1b[6;30;42m" + "Number of times granilarity was exceeded after \n encode_encrypt x add_with_new_min x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")
    else:
        print("\x1b[0;30;41m" + "Number of times granilarity was exceeded after \n encode_encrypt x add_with_new_min x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")

def test_encode_encrypt_x_add_centered_x_decrypt():
    precision = 8
    padding = 4
    torus_bit = 32
    std_dev = pow(2,-19)
    p = pow(2, precision)
    q = pow(2, torus_bit)

    # Encoder
    min1, max1 = generate_random_interval()
    min2, max2 = generate_random_interval()
    max2 = min2 + max1 - min1
    margin1 = (max1 - min1)/(p-1)
    delta1 = max1 - min1 + margin1
    granularity = (max1 - min1) / p
    k = 4
    enc1 = np.array([min1, delta1, precision, padding])
    margin2 = (max2 - min2)/(p-1)
    delta2 = max2 - min2 + margin2
    enc2 = np.array([min2, delta2, precision, padding])

    # Secret Key
    secret_key = keygen(k)

    i = 0
    for j in range(100):
        # Generate Random Messages
        delta = (max1 - min1)/4.0 + granularity/2.0
        message1 = (min1 + delta) + (np.random.rand()*((min1 + delta1 - delta)-(min1 + delta)))
        message2 = (min2 + delta) + (np.random.rand()*((min2 + delta2 - delta)-(min2 + delta)))

        # Encode & Encrypt
        ct1, var1, enc1 = encode_encrypt(message1, secret_key, enc1, std_dev, q)
        ct2, var2, enc2 = encode_encrypt(message2, secret_key, enc2, std_dev, q)

        # Compute the multiplication between ciphertext and message2
        ct_add, var_add, enc_add = add_centered(ct1, var1, enc1, ct2, var2, enc2, p, q)

        # Decrypt & Decode
        message_star = decrypt_decode(ct_add, secret_key, enc_add, q)

        # Test if error is within bounds
        if (np.abs((message1 + message2) - message_star) >= granularity):
            i += 1
            print(message1, " + ", message2, " = ", message1 + message2, "  ->  ", message_star)
            print("Granularity Exceeded in Dynamic Centered Addition: ", np.abs((message1 + message2) - message_star), " < ", granularity)
    if i==0:
        print("\x1b[6;30;42m" + "Number of times granilarity was exceeded after \n encode_encrypt x add_centered x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")
    else:
        print("\x1b[0;30;41m" + "Number of times granilarity was exceeded after \n encode_encrypt x add_centered x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")

def test_encode_encrypt_x_add_x_decrypt():
    min, max = generate_random_interval()
    min2, max2 = generate_random_interval()
    max2 = max - min + min2
    precision = 8
    padding = 4
    padding += 1 # Addition needs one extra bit
    torus_bit = 32
    std_dev = pow(2,-19)
    p = pow(2, precision)
    q = pow(2, torus_bit)

    # Encoder
    margin = (max - min)/(p-1)
    margin2 = (max2 - min2)/(p-1)
    delta = max - min + margin
    delta2 = max2 - min2 + margin2
    granularity = (max - min) / p
    granularity2 = (max2 - min2) / p
    k = 4
    enc = np.array([min, delta, precision, padding])
    enc2 = np.array([min2, delta2, precision, padding])

    # Secret Key
    secret_key = keygen(k)

    i_add = 0
    i_sub = 0
    for j in range(100):
        # Generate Random Messages
        message1 = min + (np.random.rand()*(max-min))
        message2 = min2 + (np.random.rand()*(max2-min2))

        # Encode & Encrypt
        ciphertext1, var1, enc1 = encode_encrypt(message1, secret_key, enc, std_dev, q)
        ciphertext2, var2, enc2 = encode_encrypt(message2, secret_key, enc2, std_dev, q)

        # Addition ciphertexts
        ciphertext_add, var_add, enc_add = lwe_addition(ciphertext1, var1, enc1, ciphertext2, var2, enc2, exact=0, q=q)
        ciphertext_sub, var_sub, enc_sub = lwe_subtraction(ciphertext1, var1, enc1, ciphertext2, var2, enc2, exact=1, q=q)

        # Decrypt & Decode
        message_add_star = decrypt_decode(ciphertext_add, secret_key, enc_add, q)
        message_sub_star = decrypt_decode(ciphertext_sub, secret_key, enc_sub, q)

        # Test if error is within bounds
        if (np.abs((message1 + message2 - message_add_star)) >= granularity):
            i_add += 1
            print(message1, " + ", message2, " = ", message1 + message2, "  ->  ", message_add_star)
            print("Granularity Exceeded in Addition: ", np.abs((message1 + message2 - message_add_star)), " < ", granularity)
        if (np.abs((message1 - message2 - message_sub_star)) >= granularity):
            i_sub += 1
            print(message1, " - ", message2, " = ", message1 - message2, "  ->  ", message_sub_star)
            print("Granularity Exceeded in Subtraction: ", np.abs((message1 - message2 - message_sub_star)), " < ", granularity)
    if i_add==0:
        print("\x1b[6;30;42m" + "Number of times granilarity was exceeded after \n encode_encrypt x lwe_addition x decrypt_decode: " + str(i_add) + "\n" + "\x1b[0m")
    else:
        print("\x1b[0;30;41m" + "Number of times granilarity was exceeded after \n encode_encrypt x lwe_addition x decrypt_decode: " + str(i_add) + "\n" + "\x1b[0m")
    if i_sub==0:
        print("\x1b[6;30;42m" + "Number of times granilarity was exceeded after \n encode_encrypt x lwe_subtraction x decrypt_decode: " + str(i_sub) + "\n" + "\x1b[0m")
    else:
        print("\x1b[0;30;41m" + "Number of times granilarity was exceeded after \n encode_encrypt x lwe_subtraction x decrypt_decode: " + str(i_sub) + "\n" + "\x1b[0m")

def test_encode_encrypt_x_mul_constant_static_encoder_x_decrypt():
    precision = 8
    padding = 4
    torus_bit = 32
    std_dev = pow(2,-19)
    p = pow(2, precision)
    q = pow(2, torus_bit)

    # Encoder
    min, max = generate_random_centered_interval()
    margin = (max - min)/(p-1)
    delta = max - min + margin
    granularity = (max - min) / p
    k = 4
    enc = np.array([min, delta, precision, padding])

    b = np.minimum(np.abs(min), np.abs(max)) / 20.0

    # Secret Key
    secret_key = keygen(k)

    i = 0
    for j in range(100):
        # Generate Random Messages
        message1 = -b + (np.random.rand()*(b-(-b)))
        message2 = np.int64(-b + (np.random.rand()*(b-(-b))))

        # Encode & Encrypt
        ct1, var1, enc1 = encode_encrypt(message1, secret_key, enc, std_dev, q)

        # Compute the multiplication between ciphertext and message2
        ct_mul, var_mul, enc_mul = mul_constant_static_encoder(ct1, var1, enc1, message2, p, q)

        # Decrypt & Decode
        message_star = decrypt_decode(ct_mul, secret_key, enc_mul, q)

        # Test if error is within bounds
        if (np.abs((message1 * message2) - message_star) >= granularity):
            i += 1
            print("Min: " + str(min) + ", max: " + str(max))
            print(message1, " x ", message2, " = ", message1 * message2, "  ->  ", message_star)
            print("Granularity Exceeded in Static Multiplication with a Constant: ", np.abs((message1 * message2) - message_star), " < ", granularity)
    if i==0:
        print("\x1b[6;30;42m" + "Number of times granilarity was exceeded after \n encode_encrypt x mul_constant_static_encoder x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")
    else:
        print("\x1b[0;30;41m" + "Number of times granilarity was exceeded after \n encode_encrypt x mul_constant_static_encoder x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")

def test_encode_encrypt_x_mul_constant_with_padding_x_decrypt():
    precision = 12
    padding = 3+12
    nb_bit_padding_mult = precision
    torus_bit = 32
    std_dev = pow(2,-39)
    p = pow(2, precision)
    q = pow(2, torus_bit)

    # Encoder
    min, max = generate_random_centered_interval()
    margin = (max - min)/(p-1)
    delta = max - min + margin
    granularity = (max - min) / p
    k = 4
    enc = np.array([min, delta, precision, padding])

    b = (np.random.randint(0, 300, 1)+3)[0]

    # Secret Key
    secret_key = keygen(k)

    i = 0
    for j in range(100):
        # Generate Random Messages
        message1 = min + (np.random.rand()*(max-min))
        message2 = -b + (np.random.rand()*(b-(-b)))

        # Encode & Encrypt
        ct1, var1, enc1 = encode_encrypt(message1, secret_key, enc, std_dev, q)

        # Multiply Ciphertext and Message2
        ciphertext_mul, var_mul, enc_mul = mul_constant_with_padding(ct1, var1, enc1, message2, b, nb_bit_padding_mult, p, q)

        # Decrypt & Decode
        message_star = decrypt_decode(ciphertext_mul, secret_key, enc_mul, q)

        new_granularity = enc_mul[1] / pow(2.0, enc_mul[2])
        # Test if error is within bounds
        if (np.abs((message1 * message2 - message_star)) >= new_granularity):
            i += 1
            print(message1, " * ", message2, " = ", message1 * message2, "  ->  ", message_star)
            print("Granularity Exceeded in Multiplication with a Constant: ", np.abs((message1 * message2 - message_star)), " < ", new_granularity)
    if i==0:
        print("\x1b[6;30;42m" + "Number of times granilarity was exceeded after \n encode_encrypt x mul_constant_with_padding x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")
    else:
        print("\x1b[0;30;41m" + "Number of times granilarity was exceeded after \n encode_encrypt x mul_constant_with_padding x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")


def test_encode_encrypt_x_opposite_x_decrypt():
    precision = 8
    padding = 4
    torus_bit = 32
    std_dev = pow(2,-19)
    p = pow(2, precision)
    q = pow(2, torus_bit)

    # Encoder
    min, max = generate_random_interval()
    margin = (max - min)/(p-1)
    delta = max - min + margin
    granularity = (max - min) / p
    k = 4
    enc = np.array([min, delta, precision, padding])

    # Secret Key
    secret_key = keygen(k)

    i = 0
    for j in range(100):
        # Generate Random Messages
        message = min + (np.random.rand()*(max-min))

        # Encode & Encrypt
        ct1, var1, enc1 = encode_encrypt(message, secret_key, enc, std_dev, q)

        # Compute the opposite of the ciphertext
        ct_opposite, enc_opposite = opposite(ct1, enc1, q)

        # Decrypt & Decode
        message_star = decrypt_decode(ct_opposite, secret_key, enc_opposite, q)

        # Test if error is within bounds
        if (np.abs((-message - message_star)) >= granularity):
            i += 1
            print(message, " x -1 = ", -message, "  ->  ", message_star)
            print("Granularity Exceeded in opposite: ", np.abs((-message - message_star)), " < ", granularity)
    if i==0:
        print("\x1b[6;30;42m" + "Number of times granilarity was exceeded after \n encode_encrypt x opposite x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")
    else:
        print("\x1b[0;30;41m" + "Number of times granilarity was exceeded after \n encode_encrypt x opposite x decrypt_decode: " + str(i) + "\n" + "\x1b[0m")

def main():
    print("========================")
    print("== Test LWE Functions ==")
    print("========================\n")

    print("== Test LWE Encode_Encrypt/Decrypt_Decode ==")
    test_encode_encrypt_x_decrypt()
    print("== Test LWE Static Addition with Constant ==")
    test_encode_encrypt_x_add_constant_static_encoder_x_decrypt()
    print("== Test LWE Dynamic Addition with Constant ==")
    test_encode_encrypt_x_add_constant_dynamic_encoder_decrypt()
    print("== Test LWE Addition with New Min ==")
    test_encode_encrypt_x_add_with_new_min_x_decrypt()
    print("== Test LWE Centered Addition ==")
    test_encode_encrypt_x_add_centered_x_decrypt()
    print("== Test LWE Addition ==")
    test_encode_encrypt_x_add_x_decrypt()
    print("== Test LWE Static Multiplication with Constant ==")
    test_encode_encrypt_x_mul_constant_static_encoder_x_decrypt()
    print("== Test LWE Multiplication with Constant ==")
    test_encode_encrypt_x_mul_constant_with_padding_x_decrypt()
    print("== Test LWE Opposite ==")
    test_encode_encrypt_x_opposite_x_decrypt()

if __name__ == "__main__":
    main()
