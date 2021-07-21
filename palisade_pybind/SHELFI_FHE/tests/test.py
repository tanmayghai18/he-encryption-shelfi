# -*- coding: utf-8 -*-
import SHELFI_FHE as m
from random import random

#if we want to generate the encryption keys for the first time
#m.genCryptoContextAndKeyGen("ckks")
data_dimesions = 1000

#scaling factor for each of 3 learners

scalingFactors = m.FloatVector()
scalingFactors.push_back(0.5)
scalingFactors.push_back(0.2)
scalingFactors.push_back(0.3)

scalingFactors_actual = [0.5,0.2,0.3]


learner1_data_actual = [];
learner2_data_actual = [];
learner3_data_actual = [];


learner1_data_layer_1 = m.ComplexVector()
learner2_data_layer_1 = m.ComplexVector()
learner3_data_layer_1 = m.ComplexVector()


for i in range(data_dimesions):
	val1 = random();
	val2 = random();
	val3 = random();

	learner1_data_actual.append(val1)
	learner2_data_actual.append(val2)
	learner3_data_actual.append(val3)

	learner1_data_layer_1.push_back(complex(val1,0))
	learner2_data_layer_1.push_back(complex(val2,0))
	learner3_data_layer_1.push_back(complex(val3,0))


#encrypting

enc_res_learner_1 =  m.encryption("ckks", learner1_data_layer_1)
enc_res_learner_2 =  m.encryption("ckks", learner2_data_layer_1)
enc_res_learner_3 =  m.encryption("ckks", learner3_data_layer_1)


three_learners_enc_data = m.StringList()
three_learners_enc_data.push_back(enc_res_learner_1)
three_learners_enc_data.push_back(enc_res_learner_2)
three_learners_enc_data.push_back(enc_res_learner_3)



#weighted average

PWA_res =  m.computeWeightedAverage("ckks", three_learners_enc_data, scalingFactors)


#decryption required information about dimension of each layer of model




#decryption

dec_res = m.decryption("ckks", PWA_res, data_dimesions) 

result = []


learner1_data_actual = [element * scalingFactors_actual[0] for element in learner1_data_actual]
learner2_data_actual = [element * scalingFactors_actual[1] for element in learner2_data_actual]
learner3_data_actual = [element * scalingFactors_actual[2] for element in learner3_data_actual]

for i in range(len(learner1_data_actual)):
	result.append(learner1_data_actual[i] + learner2_data_actual[i] + learner3_data_actual[i])



#printing result

j = 0
for i in (dec_res):
		print("computed: "+str(i)+" "+"actual: "+str(result[j]))
		j = j+1

