#### Explicit path addition in order to include the pybind11 *.so extension
import SHELFI_FHE as m

import numpy as np
import gc

#from utils.logging.metis_logger import MetisLogger as metis_logger

FHE_helper = m.FHE_Helper("ckks", 8192, 52)
FHE_helper.load_crypto_params()


def encrypt_compute_decrypt(models, models_scaling_factors, total_model_parameters):
	encoded_models = list()
	for model in models:
		encoded_model = FHE_helper.encrypt(model)
		encoded_models.append(encoded_model)
		# Delete encoded model object; this is an FHE library instance.
		del encoded_model

	pwa_res = FHE_helper.computeWeightedAverage(encoded_models, models_scaling_factors)
	dec_res = FHE_helper.decrypt(pwa_res, total_model_parameters)

	# Delete the privately weighted aggregation model object; this is an FHE library instance.
	del pwa_res

	# Clear the list of encoded models.
	encoded_models.clear()

	return dec_res


def encrypted_aggregation(learners_models, learners_weighting_values):
	norm_factor = sum(learners_weighting_values)
	learners_weighting_values = [float(val / norm_factor) for val in learners_weighting_values]



	base_model = learners_models[0]
	model_matrices_dtype = [matrix.dtype for matrix in base_model]
	model_matrices_shapes = [matrix.shape for matrix in base_model]
	model_matrices_cardinality = [matrix.size for matrix in base_model]
	total_model_parameters = sum(model_matrices_cardinality)

	#for midx, card in enumerate(model_matrices_cardinality):
	#	print("Matrix: {}, Cardinality: {}".format(str(midx), str(card)))

	#metis_logger.info("Starting Private Weighted Aggregation (PWA) for {} parameters.".format(
		#str(total_model_parameters)))
	# Concatenate all elements of a list of numpy elements into a single numpy array.
	#learners_models = [np.concatenate(model).ravel() for model in learners_models]

	#print(learners_models)
	#print(learners_weighting_values)
	#print("total params:"+str(total_model_parameters))


	dec_agg_res = encrypt_compute_decrypt(learners_models, learners_weighting_values, total_model_parameters)
	#metis_logger.info("Completed Private Weighted Aggregation (PWA) for {} parameters.".format(
		#str(total_model_parameters)))

	# Convert it to python list - due to subscribing
	aggregated_model = dec_agg_res
	tmp_final_model = []
	parameter_offset = 0
	for matrix_cardinality in model_matrices_cardinality:
		tmp_final_model.append(aggregated_model[parameter_offset : parameter_offset + matrix_cardinality])
		parameter_offset += matrix_cardinality

	# Construct the final model by bringing each array back to its required dimension and data type.
	final_model = []
	for midx, aggregated_matrix in enumerate(tmp_final_model):
		final_matrix = [float(val) for val in aggregated_matrix]
		final_matrix = np.array(final_matrix).astype(model_matrices_dtype[midx])
		final_matrix = final_matrix.reshape(model_matrices_shapes[midx])
		final_model.append(final_matrix)

	# Delete the decrypted aggregation object; this is an FHE library instance.
	del dec_agg_res
	# Clear any obsolete objects!
	gc.collect()

	return final_model


# Dummy test example to evaluate the above functions!
if __name__ == "__main__":
	iterations = range(0, 2)
	num_models = 2
	for i in iterations:
		print("Iteration: ", i)
		model1 = [np.array([[[1.0, 2.0], [3.0, 4.0]], [[5.0, 6.0], [7.0, 8.0]]]), np.array([[[9.0, 10.0], [11.0, 12.0]], [[13.0, 14.0], [15.0, 16.0]]])]
		model2 = [np.array([[[5.0, 6.0], [7.0, 8.0]], [[9.0, 10.0], [11.0, 12.0]]]), np.array([[[13.0, 14.0], [15.0, 16.0]], [[17.0, 18.0], [19.0, 20.0]]])]
		
		models = [model1,model2]
		models_contribution_values = [1/num_models] * num_models
		model = encrypted_aggregation(models, models_contribution_values)
		print("PWA-model:")
		for matrix in model:
			print(matrix)
