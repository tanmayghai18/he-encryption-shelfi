import sealfhe

context, public_key, secret_key, encryptor, evaluator, decryptor = sealfhe.gen_crypto_parms()

# ckks_encoder = CKKSEncoder(context)
# slot_count = ckks_encoder.slot_count()

# for i in range(0, 5):
#     print("Iteration: ", i)
#     model1 = [np.array([[[1.0, 2.0], [3.0, 4.0]], [[5.0, 6.0], [7.0, 8.0]]]), np.array([[[9.0, 10.0], [11.0, 12.0]], [[13.0, 14.0], [15.0, 16.0]]])]
#     model2 = [np.array([[[5.0, 6.0], [7.0, 8.0]], [[9.0, 10.0], [11.0, 12.0]]]), np.array([[[13.0, 14.0], [15.0, 16.0]], [[17.0, 18.0], [19.0, 20.0]]])]
#     model3 = [np.array([[[5.0, 6.0], [7.0, 8.0]], [[9.0, 10.0], [11.0, 12.0]]]), np.array([[[13.0, 14.0], [15.0, 16.0]], [[17.0, 18.0], [19.0, 20.0]]])]

#     models = [model1, model2, model3]
#     num_models = len(models)
#     models_contribution_values = [1 / num_models] * num_models

#     shape, enc_matrix = encrypt(ckks_encoder, encryptor, model1)
#     print(f'Inputted model: {model1}')
#     #print(np.concatenate(model1, axis=0).shape)

#     dec_matrix = decrypt(shape, ckks_encoder, decryptor, enc_matrix)
#     print(f'Outputted model: {dec_matrix}')
#     #print(dec_matrix.shape)