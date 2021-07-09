# -*- coding: utf-8 -*-
import SHELFI_FHE as m


#if we want to generate the encryption keys for the first time
#m.genCryptoContextAndKeyGen("ckks")


learner1_Data = m.VecVecComplex()

learner1_data_layer_1 = m.ComplexVector()
learner1_data_layer_1.push_back(complex(1.1,0))
learner1_data_layer_1.push_back(complex(2.1,0))
learner1_data_layer_1.push_back(complex(3.1,0))

learner1_data_layer_2 = m.ComplexVector()
learner1_data_layer_2.push_back(complex(4.1,0))
learner1_data_layer_2.push_back(complex(5.1,0))
learner1_data_layer_2.push_back(complex(6.1,0))

learner1_Data.push_back(learner1_data_layer_1)
learner1_Data.push_back(learner1_data_layer_2)



learner2_Data = m.VecVecComplex()

learner2_data_layer_1 = m.ComplexVector()
learner2_data_layer_1.push_back(complex(7.1,0))
learner2_data_layer_1.push_back(complex(8.1,0))
learner2_data_layer_1.push_back(complex(9.1,0))

learner2_data_layer_2 = m.ComplexVector()
learner2_data_layer_2.push_back(complex(10.1,0))
learner2_data_layer_2.push_back(complex(11.1,0))
learner2_data_layer_2.push_back(complex(12.1,0))

learner2_Data.push_back(learner2_data_layer_1)
learner2_Data.push_back(learner2_data_layer_2)



learner3_Data = m.VecVecComplex()

learner3_data_layer_1 = m.ComplexVector()
learner3_data_layer_1.push_back(complex(13.1,0))
learner3_data_layer_1.push_back(complex(14.1,0))
learner3_data_layer_1.push_back(complex(15.1,0))

learner3_data_layer_2 = m.ComplexVector()
learner3_data_layer_2.push_back(complex(16.1,0))
learner3_data_layer_2.push_back(complex(17.1,0))
learner3_data_layer_2.push_back(complex(18.1,0))

learner3_Data.push_back(learner3_data_layer_1)
learner3_Data.push_back(learner3_data_layer_2)

#encrypting

enc_res_learner_1 =  m.encryption("ckks", learner1_Data)
enc_res_learner_2 =  m.encryption("ckks", learner2_Data)
enc_res_learner_3 =  m.encryption("ckks", learner3_Data)


three_learners_enc_data = m.StringList()
three_learners_enc_data.push_back(enc_res_learner_1)
three_learners_enc_data.push_back(enc_res_learner_2)
three_learners_enc_data.push_back(enc_res_learner_3)

#scaling factor for each of 3 learners

scalingFactors = m.FloatVector()
scalingFactors.push_back(0.5)
scalingFactors.push_back(0.2)
scalingFactors.push_back(0.3)

#weighted average

PWA_res =  m.computeWeightedAverage("ckks", three_learners_enc_data, scalingFactors)


#decryption required information about dimension of each layer of model

data_dimesions = m.IntVector()
data_dimesions.push_back(3)
data_dimesions.push_back(3)


#decryption

dec_res = m.decryption("ckks", PWA_res, data_dimesions) 


#printing result

for i in dec_res:
	for j in i:
		print(j)

