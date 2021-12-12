# -*- coding: utf-8 -*-
import SHELFI_FHE as m
from random import random
import numpy as np



data_dimesions = 5

#paillier scheme currenlty doesnt support weightage
scalingFactors = [0.25,0.25, 0.25, 0.25]


#print("python init")

FHE_helper = m.FHE_Helper("paillier", 0,0, 4)

#print("python init done")

#FHE_helper.genCryptoContextAndKeyGen()

#print("python gen done")

FHE_helper.load_crypto_params()





learner1_data_actual = [];
learner2_data_actual = [];
learner3_data_actual = [];
learner4_data_actual = [];


learner1_data_layer_1 = np.random.rand(data_dimesions)
learner2_data_layer_1 = np.random.rand(data_dimesions)
learner3_data_layer_1 = np.random.rand(data_dimesions)
learner4_data_layer_1 = np.random.rand(data_dimesions)


for i in range(data_dimesions):
	
	learner1_data_actual.append(learner1_data_layer_1[i])
	learner2_data_actual.append(learner2_data_layer_1[i])
	learner3_data_actual.append(learner3_data_layer_1[i])
	learner4_data_actual.append(learner4_data_layer_1[i])






#print(learner1_data_layer_1)
#print(learner1_data_actual)

#print(learner2_data_layer_1)
#print(learner2_data_actual)

#print(learner3_data_actual)






#encrypting

enc_res_learner_1 =  FHE_helper.encrypt(learner1_data_layer_1)
enc_res_learner_2 =  FHE_helper.encrypt(learner2_data_layer_1)
enc_res_learner_3 =  FHE_helper.encrypt(learner3_data_layer_1)
enc_res_learner_4 =  FHE_helper.encrypt(learner4_data_layer_1)


'''

dec_res1 = FHE_helper.decrypt(enc_res_learner_1, data_dimesions) 
dec_res2 = FHE_helper.decrypt(enc_res_learner_2, data_dimesions) 
dec_res3 = FHE_helper.decrypt(enc_res_learner_3, data_dimesions) 



print(dec_res1)
print(dec_res2)
print(dec_res3)
'''
 


three_learners_enc_data = [enc_res_learner_1, enc_res_learner_2, enc_res_learner_3, enc_res_learner_4]



#weighted average

PWA_res =  FHE_helper.computeWeightedAverage(three_learners_enc_data, scalingFactors)



#decryption required information about dimension of each layer of model




#decryption

dec_res = FHE_helper.decrypt(PWA_res, data_dimesions) 




result = []


learner1_data_actual = [element * scalingFactors[0] for element in learner1_data_actual]
learner2_data_actual = [element * scalingFactors[1] for element in learner2_data_actual]
learner3_data_actual = [element * scalingFactors[2] for element in learner3_data_actual]
learner4_data_actual = [element * scalingFactors[3] for element in learner4_data_actual]

for i in range(len(learner1_data_actual)):
	result.append(learner1_data_actual[i] + learner2_data_actual[i]+ learner3_data_actual[i]+ learner4_data_actual[i])



#printing result

j = 0

for i in (dec_res):
		print("computed: "+str(i)+" "+"actual: "+str(result[j]))
		j = j+1

