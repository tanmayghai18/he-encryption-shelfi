
#include "utils.h"
#include <time.h>
#include <omp.h>
//#include <map>
//#include"cnpy.h"

void benchmarkNaiveApproach(paillier_pubkey_t* public_key, paillier_prvkey_t* private_key){


	std::vector<unsigned int> params;

	srand(time(NULL));

	for(int i=0; i<noOfParams; i++){

		params.push_back(rand());

	}


	std::vector<std::string> packed_params_vec = pack_params(params);

	//std::cout<<"Paked params list size: "<<packed_params_vec.size()<<std::endl;
	

	paillier_plaintext_t*** learners_plaintext = (paillier_plaintext_t***) malloc(totalLearners * sizeof(paillier_plaintext_t**));

	for(int i=0; i<totalLearners; i++){

		learners_plaintext[i] = paramsArrayfromVector(packed_params_vec);

	}



	paillier_ciphertext_t*** learners_ciphertext = (paillier_ciphertext_t***) malloc(totalLearners * sizeof(paillier_ciphertext_t**));
	paillier_ciphertext_t** ciphertext_result = (paillier_ciphertext_t**) malloc(noOfParams * sizeof(paillier_ciphertext_t*));

	paillier_plaintext_t** sum_plaintext;

	double start_time;
	double time_elapsed;



	printf("Encrypting..\n");

	start_time = omp_get_wtime();

	int packed_size = ceil((float)noOfParams/(float)(nums_to_pack));

	#pragma omp parallel for 
	for(int i=0; i<totalLearners; i++){

		learners_ciphertext[i] = encryptParams(learners_plaintext[i], packed_size, public_key);

	}

	time_elapsed = omp_get_wtime() - start_time;


	printf("Time taken by a learner to encrypt %d parameters: %fs\n", noOfParams, time_elapsed/totalLearners);


	//freeing plaintext

	for(int i=0; i<totalLearners; i++){

		for(int j=0; j<packed_size; j++){

			free(learners_plaintext[i][j]);

		}

		free(learners_plaintext[i]);

	}

	free(learners_plaintext);

	

	printf("Adding..\n");


	start_time = omp_get_wtime();

	calculate_homomorphic_sum(ciphertext_result, learners_ciphertext, packed_size, totalLearners, public_key);

	time_elapsed = omp_get_wtime() - start_time;


	printf("Time taken by controller to add %d encrypted parameters of %d learners: %fs\n", noOfParams, totalLearners, time_elapsed);


	printf("Decrypting..\n");

	start_time = omp_get_wtime();

	sum_plaintext = decryptParams(ciphertext_result, packed_size, public_key, private_key);

	time_elapsed = omp_get_wtime() - start_time;

	printf("Time taken by a learner to decrypt %d encrypted parameters: %fs\n", noOfParams, time_elapsed);



	for(int i=0; i<totalLearners; i++){

		for(int j=0; j<packed_size; j++){

			free(learners_ciphertext[i][j]);

		}

		free(learners_ciphertext[i]);

	}

	free(learners_ciphertext);



}








void benchmarkOnlinePhase(){

	
	double start_time;
	double time_elapsed;


	int** learners_data = new int*[totalLearners];


	int* learners_data_sum = new int[noOfParams]; 


	int** learners_randomness = new int*[totalLearners];

	for(int i=0; i<totalLearners; i++){

		learners_data[i] = new int[noOfParams];

		for(int j=0; j<noOfParams; j++){

			learners_data[i][j] = j; 

		}

	}


	for(int i=0; i<totalLearners; i++){

		learners_randomness[i] = new int[noOfParams];


		for(int j=0; j<noOfParams; j++){

			learners_randomness[i][j] = j; 

		}

	}


	start_time = omp_get_wtime();

	//#pragma omp parallel for
	for(int i=0; i<totalLearners; i++){

		for(int j=0; j<noOfParams; j++){

			learners_data[i][j] = learners_data[i][j] + learners_randomness[i][j]; 

		}

	}


	time_elapsed = omp_get_wtime() - start_time;

	printf("Time taken by a learner to add randomness in %d parameters: %fs\n", noOfParams, time_elapsed/totalLearners);



	start_time = omp_get_wtime();
	
	//#pragma omp parallel for
	for(int i=0; i<noOfParams; i++){

		learners_data_sum[i] = learners_data[0][i];

		for(int j=0; j<totalLearners-1; j++){

			learners_data_sum[i] = learners_data_sum[i] + learners_data[j+1][i]; 


		}

	}


	time_elapsed = omp_get_wtime() - start_time;

	printf("Time taken by the controller to sum %d parameters from %d learners: %fs\n", noOfParams, totalLearners, time_elapsed);



	start_time = omp_get_wtime();

	//#pragma omp parallel for
	for(int i=0; i<totalLearners; i++){

		for(int j=0; j<noOfParams; j++){

			learners_data[i][j] = learners_data[i][j] - learners_randomness[i][j]; 

		}

	}


	time_elapsed = omp_get_wtime() - start_time;

	printf("Time taken by a learner to subtract randomness in %d parameters: %fs\n", noOfParams, time_elapsed/totalLearners);





}



int main(){


	printf("Start\n");

	paillier_pubkey_t* public_key;
	paillier_prvkey_t* private_key; 

	paillier_keygen(modulusbits, &public_key, &private_key, get_rand);


	std::cout<<"\n\nBenchmarking Naive Approach/Offline Phase\n"<<std::endl;

	benchmarkNaiveApproach(public_key, private_key);

	std::cout<<"\n\nBenchmarking Online Phase\n"<<std::endl;

	benchmarkOnlinePhase();



}
