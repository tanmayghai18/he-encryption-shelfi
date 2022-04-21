from seal import EncryptionParameters, SEALContext, CKKSEncoder, KeyGenerator, Encryptor, Evaluator, Decryptor, scheme_type, CoeffModulus
import numpy as np


def gen_crypto_parms():
    parms = EncryptionParameters(scheme_type.ckks)
    poly_modulus_degree = 8192
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


if __name__ == "__main__":
    context, public_key, secret_key, encryptor, evaluator, decryptor = gen_crypto_parms()

    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()

    for i in range(0, 5):
        print("Iteration: ", i)
        model1 = [np.array([[[1.0, 2.0], [3.0, 4.0]], [[5.0, 6.0], [7.0, 8.0]]]), np.array([[[9.0, 10.0], [11.0, 12.0]], [[13.0, 14.0], [15.0, 16.0]]])]
        model2 = [np.array([[[5.0, 6.0], [7.0, 8.0]], [[9.0, 10.0], [11.0, 12.0]]]), np.array([[[13.0, 14.0], [15.0, 16.0]], [[17.0, 18.0], [19.0, 20.0]]])]
        model3 = [np.array([[[5.0, 6.0], [7.0, 8.0]], [[9.0, 10.0], [11.0, 12.0]]]), np.array([[[13.0, 14.0], [15.0, 16.0]], [[17.0, 18.0], [19.0, 20.0]]])]

        models = [model1, model2, model3]
        num_models = len(models)
        models_contribution_values = [1 / num_models] * num_models

        shape, enc_matrix = encrypt(ckks_encoder, encryptor, model1)
        print(f'Inputted model: {model1}')
        #print(np.concatenate(model1, axis=0).shape)

        dec_matrix = decrypt(shape, ckks_encoder, decryptor, enc_matrix)
        print(f'Outputted model: {dec_matrix}')
        #print(dec_matrix.shape)
