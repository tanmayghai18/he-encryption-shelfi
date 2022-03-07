# -*- coding: utf-8 -*-
import SHELFI_FHE as m
from random import random
import numpy as np

import time


data_dimesions = 10000

learners = 4
crypto_dir = "../resources/cryptoparams/"
randomness_dir = "../resources/random_params/"
modulus_bits = 2048
num_bits = 17
precision_bits = 13

FHE_helper = m.FHE_Helper("paillier", 0, 0, learners, crypto_dir, randomness_dir, modulus_bits, num_bits, precision_bits)


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
#print(learner2_data_layer_1)
#print(learner3_data_layer_1)
#print(learner4_data_layer_1)



############### offline phase ###################


#randomness is generated per iteration
#specify the iteration for which you want to generate randomness

iteration = 0
learner_rands = []

l0_rand = FHE_helper.genPaillierRandOffline( data_dimesions, iteration)

#other learners also generate their own randomness locally
#l1_rand = FHE_helper.genPaillierRandOffline( data_dimesions, iteration)
#l2_rand = FHE_helper.genPaillierRandOffline( data_dimesions, iteration)
#l3_rand = FHE_helper.genPaillierRandOffline( data_dimesions, iteration)



#the controller receives the encrypted randomness from all learners and adds it

learner_rands.append(l0_rand)
#learner_rands.append(l1_rand)
#learner_rands.append(l2_rand)
#learner_rands.append(l3_rand)


learner_rand_sum =  FHE_helper.addPaillierRandOffline(learner_rands)


#controller sends back the sum of encrypted randomness to each learner
#each learner decrypts and stores the sum locally

FHE_helper.storePaillierRandSumOffline( learner_rand_sum, data_dimesions, iteration)




################ online phase ###############

#each learner encrypts their parameters locally by subtracting randomness

l0_enc = FHE_helper.encrypt( learner1_data_layer_1, iteration) 
#l1_enc = FHE_helper.encrypt( learner2_data_layer_1, iteration) 
#l2_enc = FHE_helper.encrypt( learner3_data_layer_1, iteration) 
#l3_enc = FHE_helper.encrypt( learner4_data_layer_1, iteration) 

#masked parameters are sent to controller that computes weighted average

learners_enc = []
learners_enc.append(l0_enc)
#learners_enc.append(l1_enc)
#learners_enc.append(l2_enc)
#learners_enc.append(l3_enc)


weighted_avg = FHE_helper.computeWeightedAverage(learners_enc, [0,0,0,0], data_dimesions) 

 
#learners receive the masked weighted average and unmask it locally

dec_result = FHE_helper.decrypt( weighted_avg, data_dimesions, iteration)



#result = []


#for i in range(len(learner1_data_actual)):
	#result.append((learner1_data_actual[i] + learner2_data_actual[i] + learner3_data_actual[i]+ learner4_data_actual[i])/learners)






#j = 0

#for i in (dec_result):
	#print("computed: "+str(i)+" "+"actual: "+str(result[j]))
	#j = j+1









