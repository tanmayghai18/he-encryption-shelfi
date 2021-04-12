#include "utils.h"
#include <time.h>
#include <omp.h>

#include <chrono> 
using namespace std::chrono; 

void benchmark(BGN* b, PublicKey* PK){


	std::vector<unsigned int> params;

	//srand(time(NULL));

	for(int i=0; i<noOfParams; i++){

		//params.push_back(rand());

		params.push_back(10);

	}

	//std::cout<<params.size()<<std::endl;


	//std::vector<std::string> packed_params_vec = pack_params(params);

	//std::cout<<"Paked params list size: "<<packed_params_vec.size()<<std::endl;
	

	mpz_t** learners_plaintext = new mpz_t*[totalLearners];

	mpz_t** scaling_factors = new mpz_t*[totalLearners];


	for(int i=0; i<totalLearners; i++){

		learners_plaintext[i] = paramsArrayfromVector(params);
		scaling_factors[i] = paramsArrayfromVector(params);

	}

	
	element_t** learners_ciphertext = new element_t*[totalLearners];
	element_t** learners_scaling_factors = new element_t*[totalLearners];

	element_t* ciphertext_result = new element_t[noOfParams];
	

	mpz_t* sum_plaintext;




	printf("Encrypting..\n");

	auto start_time = std::chrono::steady_clock::now();

	//start_time = omp_get_wtime();

	//int packed_size = ceil((float)noOfParams/(float)(nums_to_pack));

	#pragma omp parallel for 
	for(int i=0; i<totalLearners; i++){

		//learners_ciphertext[i] = encryptParams(learners_plaintext[i], packed_size, b, PK);

		learners_ciphertext[i] = encryptParams(learners_plaintext[i], noOfParams, b, PK);

	}

	//time_elapsed = omp_get_wtime() - start_time;

	auto time_elapsed = std::chrono::steady_clock::now() - start_time;


	printf("Time taken by a learner to encrypt %d million parameters: %f seconds\n\n", 1, (((std::chrono::duration <double> (time_elapsed).count())/totalLearners)/noOfParams)*1000000);


	#pragma omp parallel for 
	for(int i=0; i<totalLearners; i++){


		learners_scaling_factors[i] = encryptParams(scaling_factors[i], noOfParams, b, PK);

	}



	//freeing plaintext

	
	for(int i=0; i<totalLearners; i++){

		for(int j=0; j<noOfParams; j++){

			mpz_clear(learners_plaintext[i][j]);

		}

		delete[] learners_plaintext[i];

	}

	delete[] learners_plaintext;


	for(int i=0; i<totalLearners; i++){

		for(int j=0; j<noOfParams; j++){

			mpz_clear(scaling_factors[i][j]);

		}

		delete[] scaling_factors[i];

	}

	delete[] scaling_factors;




	printf("Weighted Average..\n");


	//start_time = omp_get_wtime();

	start_time = std::chrono::steady_clock::now();

	//calculate_homomorphic_sum(ciphertext_result, learners_ciphertext, noOfParams, totalLearners, b, PK);


	calculate_homomorphic_multiplication(ciphertext_result, learners_ciphertext, learners_scaling_factors, noOfParams, totalLearners, b, PK);

	//time_elapsed = omp_get_wtime() - start_time;

	time_elapsed = std::chrono::steady_clock::now() - start_time;




	//printf("Time taken by a learner to scale %d encrypted parameters: %fmilli sec\n", noOfParams, (std::chrono::duration <double> (time_elapsed).count())/totalLearners);


	auto start_time1 = std::chrono::steady_clock::now();

	calculate_homomorphic_sum(ciphertext_result, learners_ciphertext, noOfParams, totalLearners, b, PK);

	//printf("Time taken by a learner to encrypt %d million parameters: %f seconds\n\n", 1, (((std::chrono::duration <double> (time_elapsed).count())/totalLearners)/noOfParams)*1000000);


	auto time_elapsed1 = std::chrono::steady_clock::now() - start_time1;

	printf("Time taken to compute weighted average of %d million encrypted parameters of %d learners: %f seconds\n\n", 1, totalLearners, (((std::chrono::duration <double> (time_elapsed1).count())/noOfParams)*1000000) + ((((std::chrono::duration <double> (time_elapsed).count())/totalLearners)/noOfParams)*1000000) );







	printf("Decrypting..\n");

	//start_time = omp_get_wtime();

	start_time = std::chrono::steady_clock::now();


	
	//sum_plaintext = decryptParams(ciphertext_result, noOfParams, b, PK);

	sum_plaintext = decryptParams(ciphertext_result, noOfParams, b, PK);

	

	//time_elapsed = omp_get_wtime() - start_time;

	time_elapsed = std::chrono::steady_clock::now() - start_time;

	printf("Time taken by a learner to decrypt %d million encrypted parameters: %f seconds\n\n", 1, (((std::chrono::duration <double> (time_elapsed).count())/noOfParams)*1000000) );


	std::cout<<"Done.."<<std::endl;


	for(int i=0; i<totalLearners; i++){

		for(int j=0; j<noOfParams; j++){

			element_clear(learners_ciphertext[i][j]);

		}

		delete[] learners_ciphertext[i];

	}

	delete[] learners_ciphertext;




}








int main(){

	BGN* b = new BGN();


	const char* paramFileName = "params.txt";
	const char* privateKeyFileName = "privateKey.txt";

	//b->generateA1Params(securityBits, paramFileName, privateKeyFileName);
	PublicKey* PK =  b->init(paramFileName, privateKeyFileName);

	std::cout<<"\n\nBenchmarking..\n"<<std::endl;



	benchmark(b, PK);

	return 0;


	











	for(int i=0; i<1000; i++){


		mpz_t msg1, msg2, msg3, msg4, msg5;

		mpz_init_set_ui(msg1, 10);
		mpz_init_set_ui(msg2, 10);
		mpz_init_set_ui(msg3, 10);
		mpz_init_set_ui(msg4, 10);
		mpz_init_set_ui(msg5, 10);

		element_t ct1, ct2, ct3, ct4, ct5, add_res, add_res1;

		b->encrypt(PK, msg1, ct1);

		std::cout<<element_length_in_bytes(ct1)<<std::endl;
		b->encrypt(PK, msg2, ct2);
		b->encrypt(PK, msg3, ct3);
		b->encrypt(PK, msg4, ct4);
		b->encrypt(PK, msg5, ct5);


		//std::cout<<"Done Enc"<<std::endl;

		b->add(PK, ct1, ct2, add_res);
		b->add(PK, ct2, add_res, add_res);
		b->add(PK, ct3, add_res, add_res);
		b->add(PK, ct4, add_res, add_res);


		//std::cout<<"Add done"<<std::endl;


		mpz_t dec_msg_add;

		b->decrypt(PK, b->q, add_res, dec_msg_add);

		gmp_printf("%s is an mpz %Zd\n", "here", dec_msg_add);





	}



	






	

















/*


	mpz_t msg1, msg2;

	mpz_init_set_ui(msg1, 100);
	mpz_init_set_ui(msg2, 200);


	element_t ct1, ct2, add_res, mul_res;


	b->encrypt(PK, msg1, ct1);
	b->encrypt(PK, msg2, ct2);


	b->multiply(PK, ct1, ct2, mul_res);

	mpz_t dec_msg_add, dec_msg_mul;;

	b->decryptMul(PK, b->q, mul_res, dec_msg_mul);

	gmp_printf("%s is an mpz %Zd\n", "here", dec_msg_mul);

*/



	/*b->add(PK, ct1, ct2, add_res);


	//element_printf("%B\n", result);

	mpz_t dec_msg;

	b->decrypt(PK, b->q, add_res, dec_msg);

	gmp_printf("%s is an mpz %Zd\n", "here", dec_msg);

*/


	





	return 0;
}