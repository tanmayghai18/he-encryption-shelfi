from seal import EncryptionParameters, SEALContext, CKKSEncoder, KeyGenerator, Encryptor, Evaluator, Decryptor, scheme_type, CoeffModulus
import numpy as np

def gen_crypto_parms():
    parms = EncryptionParameters(scheme_type.ckks)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, [60, 40, 40, 60]))
    context = SEALContext(parms)
    ckks_encoder = CKKSEncoder(context)

    #print_parameters(context)

    keygen = KeyGenerator(context)
    secret_key = keygen.secret_key()
    public_key = keygen.create_public_key()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    return context, public_key, secret_key, encryptor, evaluator, decryptor


def encrypt(encoder, encryptor, matrix):
    print("Encrypting learner matrix model!")
    scale = 2.0**40
    matrix = np.concatenate(matrix, axis=0)
    plain_matrix = encoder.encode(matrix.flatten(), scale)
    return matrix.shape, encryptor.encrypt(plain_matrix)


def decrypt(shape, encoder, decryptor, enc_matrix):
    print("Decrypting learner matrix model!")
    dec_matrix = decryptor.decrypt(enc_matrix)
    vec = encoder.decode(dec_matrix)
    return vec[:shape[0]**shape[1]].reshape(shape)