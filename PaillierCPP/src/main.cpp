
#include "PaillierUtils.h"
//#include "utils.h"
#include <time.h>
#include <omp.h>
#include <string>
#include <string.h>
//#include <map>
//#include"cnpy.h"

using namespace std;

/*void benchmarkNaiveApproach(paillier_pubkey_t* public_key, paillier_prvkey_t* private_key){


	//todo: clip before packing

	int nums_to_pack = modulusbits/(num_rep_bits + pad_zeros);
	int packed_size = ceil((float)noOfParams/(float)(nums_to_pack));


	std::vector<unsigned int> params;

	srand(time(NULL));

	for(int i=0; i<noOfParams; i++){

		params.push_back(rand() % 65535);

	}

	printParamsArray(params, params.size());


	std::vector<std::string> packed_params_vec;

	pack_params(params, packed_params_vec);

	//printParamsArray(packed_params_vec, params.size());

	std::cout<<"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"<<std::endl<<std::endl;

	for(int i=0; i<packed_params_vec.size(); i++){

		std::string bin_packed = "";

		charArrayToBinary(packed_params_vec[i], bin_packed);

		std::cout<<bin_packed<<std::endl;

	}


	std::cout<<"Done packing"<<std::endl;
	std::cout<<"Packed params list size: "<<packed_params_vec.size()<<std::endl;



	std::vector<unsigned int> unpacked_params;


	unpack_params(packed_params_vec, unpacked_params);

	std::cout<<"Done unpacking"<<std::endl;


	printParamsArray(unpacked_params, unpacked_params.size());




	paillier_plaintext_t*** learners_plaintext = (paillier_plaintext_t***) malloc(totalLearners * sizeof(paillier_plaintext_t**));

	for(int i=0; i<totalLearners; i++){

		learners_plaintext[i] = paramsArrayfromVector(packed_params_vec);

	}



	paillier_ciphertext_t*** learners_ciphertext = (paillier_ciphertext_t***) malloc(totalLearners * sizeof(paillier_ciphertext_t**));
	paillier_ciphertext_t** ciphertext_result = (paillier_ciphertext_t**) malloc(packed_size * sizeof(paillier_ciphertext_t*));

	paillier_plaintext_t** sum_plaintext;

	double start_time;
	double time_elapsed;



	printf("Encrypting..\n");

	start_time = omp_get_wtime();

	

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



	std::vector<std::string> dec_packed_params;

	std::vector<unsigned int> dec_params;



	paillierPlaintextToStr(sum_plaintext, packed_size, dec_packed_params);

	unpack_params(dec_packed_params, dec_params);







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



}*/



int main(){

	printf("Start\n");

	vector<double> params1;
	vector<double> params2;
	vector<double> params3;
	vector<double> params4;
	vector<double> params5;

	int total_params = 10;



	vector<double> scaled_down_params;
	
	vector<unsigned long int> scaled_params;
	vector<string> learner_params;

	vector<unsigned long int> unpacked_params;

	PaillierUtils* utils = new PaillierUtils(5);

	utils->genKeys("");


	//init_params(5);


	for(int i=0; i<total_params; i++){

		//float random_val = -20.0 + static_cast <float> (rand()) /( static_cast <float> (RAND_MAX/( (20.0) -(-20.0))));

		float random_val1 = 0.2134345345;
		float random_val2 = 0.1;
		float random_val3 = 0.3;
		float random_val4 = 0.2;
		float random_val5 = 0.5;


		params1.push_back(random_val1);

		//random_val = -20.0 + static_cast <float> (rand()) /( static_cast <float> (RAND_MAX/( (20.0) -(-20.0))));

		params2.push_back(random_val2);

		//random_val = -20.0 + static_cast <float> (rand()) /( static_cast <float> (RAND_MAX/( (20.0) -(-20.0))));

		params3.push_back(random_val3);

		params4.push_back(random_val4);

		params5.push_back(random_val5);

	}

	



	learner_params.push_back(utils->encryptParams(params1));
	learner_params.push_back(utils->encryptParams(params2));
	learner_params.push_back(utils->encryptParams(params3));
	learner_params.push_back(utils->encryptParams(params4));
	learner_params.push_back(utils->encryptParams(params5));




	//string results = utils->calculate_homomorphic_sum(learner_params);



	std::vector<double> res_dec = utils->decryptParams(learner_params[0], total_params);

	for(int i=0; i<total_params; i++){

		cout<<params1[i]<<" "<<params2[i]<<" "<<params3[i]<<" "<<params1[i]+params2[i]+params3[i]+params4[i]+params5[i]<<" "<<res_dec[i]<<endl;


	}

	










	return 0;






	

	
	//std::string data = std::bitset<16>(4546).to_string();

	//std::string data2 = std::bitset<16>(45462).to_string();

	/*unsigned int a = 101;
	unsigned int b = 502;


	unsigned int c = 45;
	unsigned int d = 454;
	


	unsigned int result;
	unsigned int result1;

	unsigned char* a_char = new unsigned char[modulusbits/8];
	unsigned char* b_char = new unsigned char[modulusbits/8];

	unsigned char* a_ptr = (unsigned char*)& a;
	unsigned char* b_ptr = (unsigned char*)& b;
	unsigned char* c_ptr = (unsigned char*)& c;
	unsigned char* d_ptr = (unsigned char*)& d;


	for(int i=0; i<modulusbits/8; i++){

		a_char[i] = 0;
		b_char[i] = 0;

	}



	a_char[0] = a_ptr[3];
	a_char[1] = a_ptr[2];
	a_char[2] = a_ptr[1];
	a_char[3] = a_ptr[0];


	a_char[4] = c_ptr[3];
	a_char[5] = c_ptr[2];
	a_char[6] = c_ptr[1];
	a_char[7] = c_ptr[0];	



	b_char[0] = b_ptr[3];
	b_char[1] = b_ptr[2];
	b_char[2] = b_ptr[1];
	b_char[3] = b_ptr[0];



	b_char[4] = d_ptr[3];
	b_char[5] = d_ptr[2];
	b_char[6] = d_ptr[1];
	b_char[7] = d_ptr[0];	



	paillier_plaintext_t* pt1 = paillier_plaintext_from_bytes((void*)a_char, modulusbits/8);
	paillier_plaintext_t* pt2 = paillier_plaintext_from_bytes((void*)b_char, modulusbits/8);
	

	gmp_printf("Plaintext1 object read: %Zd\n", pt1);
	gmp_printf("Plaintext2 object read: %Zd\n", pt2);   

	
	paillier_ciphertext_t* ct1 = paillier_enc(NULL, public_key, pt1, paillier_get_rand_devurandom);
	paillier_ciphertext_t* ct2 = paillier_enc(NULL, public_key, pt2, paillier_get_rand_devurandom);




	paillier_ciphertext_t* res_ct = paillier_create_enc_zero();

	paillier_mul(public_key, res_ct, ct1, ct2);

	paillier_plaintext_t* res_plains = paillier_dec(NULL, public_key, private_key, res_ct); 

	gmp_printf("Decrypted: %Zd\n", res_plains);


	unsigned char* res_plain_ans = (unsigned char*) paillier_plaintext_to_bytes( modulusbits/8, res_plains );

	unsigned char* res_sum = (unsigned char*)& result;

	unsigned char* res_sum1 = (unsigned char*)& result1;



	res_sum[3] = res_plain_ans[0];
	res_sum[2] = res_plain_ans[1];
	res_sum[1] = res_plain_ans[2];
	res_sum[0] = res_plain_ans[3];

	res_sum1[3] = res_plain_ans[4];
	res_sum1[2] = res_plain_ans[5];
	res_sum1[1] = res_plain_ans[6];
	res_sum1[0] = res_plain_ans[7];
	




	std::cout<<a+b<<" "<<c+d<<" "<<result<<" "<<result1<<std::endl;


	return 0;


*/





/*







	std::string bin_a = "00000000" + std::bitset<16>(a).to_string();
	std::string bin_b = "00000000" + std::bitset<16>(b).to_string();

	std::cout<<bin_a<<std::endl;

	std::stringstream sstream_a(bin_a);
	std::stringstream sstream_b(bin_b);

	std::cout<<"stream: "<<sstream_a.str()<<std::endl;	
	
	std::string output_a="";
	std::string output_b="";

	std::bitset<8> bits;

	while(sstream_a >> bits){

			char c = char(bits.to_ulong()+ 64);
			output_a += c;

    }


    while(sstream_b >> bits){

			char c = char(bits.to_ulong()+ 64);
			output_b += c;

    }


	std::string res;



	paillier_plaintext_t* sum_plaintext = paillier_plaintext_from_str((char *)output_a.c_str());
	paillier_plaintext_t* sum_plaintext1 = paillier_plaintext_from_str((char *)output_b.c_str());

	paillier_plaintext_t* res_plain;

	paillier_ciphertext_t* cipher1 = paillier_enc(NULL, public_key, sum_plaintext, get_rand);

	paillier_ciphertext_t* cipher2 = paillier_enc(NULL, public_key, sum_plaintext1, get_rand);


	paillier_mul(public_key, cipher1, cipher1, cipher2);

	res_plain = paillier_dec(NULL, public_key, private_key, cipher1); 


	res = paillier_plaintext_to_str(res_plain);






	std::cout<<"Here"<<std::endl;

	std::cout<<res<<std::endl;
	std::cout<<res.size()<<std::endl;

	for(int i=0; i<res.size(); i++){

		std::bitset<8> my_bset = std::bitset<8>(res[i]);

		std::cout<<my_bset.to_string()<<std::endl;

	}






	return 0;




	std::cout<<"\n\nBenchmarking Naive Approach/Offline Phase\n"<<std::endl;

	benchmarkNaiveApproach(public_key, private_key);

	std::cout<<"\n\nBenchmarking Online Phase\n"<<std::endl;

	benchmarkOnlinePhase();

*/

}
