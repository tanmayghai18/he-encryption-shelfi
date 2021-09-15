import SHELFI_FHE as m
import random
import numpy as np


total_learners = {10,100}
total_params = {pow(10,4), pow(10,6), 3*pow(10,6), 5*pow(10,6), 10*pow(10,6)}



def getInput():
	learners_str = "Select total learners from: "+ str(total_learners) + ": "
	params_str = "Select total parameters from: "+ str(total_params) + ": "
	

	learners = input(learners_str)
	params = input(params_str)

	if (int(learners) not in total_learners) or (int(params) not in total_params):
		print("Wrong input")
		quit()

	return int(learners), int(params)


def getRandomScalingFactors(start, end, size):

	x = [random.randint(start, end) for _ in range(size)]

	sum = 0.0
	for i in x:
		sum+=i

	for i in range(len(x)):
		x[i] = x[i]/sum

	return x


def initializeLearners(learners, total_learners, data_dimesions):

	for i in range(total_learners):
		learners.append(np.random.rand(int(data_dimesions/2.0), 2))


def encrypt(learners, res, FHE_helper):

	for i in learners:
		res.append(FHE_helper.encrypt(i))


def computeWeightedAveragePlain(learners_data, scalingFactors):

	result = []

	for i in range(len(learners_data)):
		result.append((learners_data[i] * scalingFactors[i]))

	sum = result[0]

	for i in range(len(result)-1):

		sum+=result[i+1]

	return sum.flatten()




def verifyEqual(dec_res, weightedAvgPlain):
	test_flag = True

	for i in range(len(dec_res)):
		a = "{:.2f}".format(dec_res[i])
		b = "{:.2f}".format(weightedAvgPlain[i])

		if a!=b:
			test_flag = False
			print("Parameter Value not Equal")
			print("Computed: "+str(dec_res[i])+" "+"Actual: "+str(weightedAvgPlain[i]))

	if test_flag == True:
		print("Computed parameters are correct.")
		print("Test passed successfully.")




def main():

	FHE_helper = m.FHE_Helper("ckks", 8192,52)
	FHE_helper.load_cyrpto_params()
    
	learners, params = getInput()

	scalingFactors = getRandomScalingFactors(1, 10, learners);

	learners_data = []
	encrypted_data = []

	initializeLearners(learners_data, learners, params)

	print("Encrypting..")
	encrypt(learners_data, encrypted_data, FHE_helper)

	print("Computing PWA..")
	PWA_res =  FHE_helper.computeWeightedAverage(encrypted_data, scalingFactors)

	print("Decrypting..")
	dec_res = FHE_helper.decrypt(PWA_res, params) 


	weightedAvgPlain = computeWeightedAveragePlain(learners_data, scalingFactors)

	print("Verifying..")

	verifyEqual(dec_res, weightedAvgPlain)














if __name__ == "__main__":
    main()