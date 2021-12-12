import numpy as np
import gc

#### Explicit path addition in order to include the pybind11 *.so extension
import sys

import SHELFI_FHE as m
from timeit import default_timer as timer


FHE_helper = m.FHE_Helper("ckks", 8192,52)
FHE_helper.load_crypto_params()



def encrypt_compute_decrypt(flatten_models, scaling_factors):

	#global total_enc_time
	#global total_dec_time
	#global total_pwa_time


	total_model_parameters = flatten_models[0].size
	encoded_models = []
	
	
	for flatten_model in flatten_models:
		
		#start = timer()
		encoded_model = FHE_helper.encrypt( flatten_model)
		#end = timer()
		
		#total_enc_time = total_enc_time+(end - start)
		
		encoded_models.append(encoded_model)
		# Clear Vector to free memory and avoid leakage!
		del encoded_model
		
	


	#start = timer()
	pwa_res = FHE_helper.computeWeightedAverage( encoded_models, scaling_factors)
	#end = timer()
	#total_pwa_time = total_pwa_time+(end - start)


	#start = timer()
	dec_res = FHE_helper.decrypt( pwa_res, total_model_parameters)
	
	#end = timer()
	#total_dec_time = total_dec_time+(end - start)

	del pwa_res

	# Clear StringList and Vector data structures to free memory and avoid leakage!
	encoded_models.clear()
	scaling_factors.clear()

	return dec_res


def encrypted_aggregation(learners_models, learners_weighting_values):
	norm_factor = sum(learners_weighting_values)
	learners_weighting_values = [float(val / norm_factor) for val in learners_weighting_values]

	model_matrices_shapes =  learners_models[0].shape
	
	aggregated_model = encrypt_compute_decrypt(learners_models, learners_weighting_values)

	final_model = aggregated_model.reshape(model_matrices_shapes)

	
	# Clear any obsolete objects!
	gc.collect()

	return final_model


# Dummy test example to evaluate the above functions!
if __name__ == "__main__":

	total_iterations = 10
	num_models = 10
	total_params = 40000
	
	
	iterations = range(0, total_iterations)
	
	
	total_time=0.0
	
	
	for i in iterations:
		#print("Iteration: ", i)
		
		model1 = np.random.rand(total_params)
		models = [model1] * num_models
		models_contribution_values = [1/num_models] * num_models
		
		#start = timer()
		model = encrypted_aggregation(models, models_contribution_values)
		#end = timer()

		#total_time = total_time + (end-start)
		
		print("Aggregation model: ")
		print(model)
		

	#print("Total time: "+str(total_time/total_iterations))
	
	
	
	
	
	
