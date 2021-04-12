#include "utils.h"


mpz_t* paramsArrayfromVector(std::vector<std::string> params){


	mpz_t* weights = new mpz_t[params.size()];

	//#pragma omp parallel for
    for(int i=0; i<params.size(); i++){

    	mpz_init_set_str(weights[i], params[i].c_str(), 10);

    }

	return weights;


}



mpz_t* paramsArrayfromVector(std::vector<unsigned int> params){


	mpz_t* weights = new mpz_t[params.size()];

	//#pragma omp parallel for
    for(int i=0; i<params.size(); i++){

    	mpz_init_set_ui(weights[i], params[i]);

    }

	return weights;


}





element_t* encryptParams(mpz_t* plaintext_arr, int size, BGN* b, PublicKey* PK){

	element_t* ciphertext_arr = new element_t[size];

	//element_printf("%B\n", ciphertext_arr[0]);

	#pragma omp parallel for
	for(int i=0; i<size; i++){

		b->encrypt(PK, plaintext_arr[i], ciphertext_arr[i]);

	}

	//element_printf("%B\n", ciphertext_arr[0]);

	return ciphertext_arr;


}



mpz_t* decryptParams(element_t* ciphertext_arr, int size, BGN* b, PublicKey* PK){

	mpz_t* plaintext_arr = new mpz_t[size];

	#pragma omp parallel for 
	for(int i=0; i<size; i++){

		b->decrypt(PK, b->q, ciphertext_arr[i], plaintext_arr[i]);

	}

	return plaintext_arr;

}




mpz_t* decryptParamsMul(element_t* ciphertext_arr, int size, BGN* b, PublicKey* PK){


	mpz_t* plaintext_arr = new mpz_t[size];

	#pragma omp parallel for 
	for(int i=0; i<size; i++){

		//std::cout<<i<<std::endl;

		b->decryptMul(PK, b->q, ciphertext_arr[i], plaintext_arr[i]);

	}

	return plaintext_arr;

}



void calculate_homomorphic_sum(element_t* ciphertext_result, element_t** ciphertext_arr, int size, int noOfLearners, BGN* b, PublicKey* PK){

	#pragma omp parallel for 
	for(int i=0; i<size; i++){

		element_init_same_as(ciphertext_result[i], ciphertext_arr[0][i]);
		element_set(ciphertext_result[i], ciphertext_arr[0][i]);

		for(int j=0; j<noOfLearners-1; j++){

			b->add(PK, ciphertext_result[i], ciphertext_arr[j+1][i], ciphertext_result[i]);

		}

	}


}


void calculate_homomorphic_multiplication(element_t* ciphertext_result, element_t** ciphertext_arr, element_t** scaling_factors, int size, int noOfLearners, BGN* b, PublicKey* PK){


	element_t** mul_result = new element_t*[noOfLearners];

	for(int i=0; i<noOfLearners; i++){

		mul_result[i] = new element_t[size];

	}



	#pragma omp parallel for 
	for(int i=0; i<noOfLearners; i++){

		for(int j=0; j<size; j++){

			b->multiply(PK, scaling_factors[i][j], ciphertext_arr[i][j], mul_result[i][j]);

		}

	}


	for(int i=0; i<noOfLearners; i++){

		for(int j=0; j<size; j++){

			element_clear(mul_result[i][j]);


		}

		delete[] mul_result[i];

	}

	delete[] mul_result;






	/*#pragma omp parallel for 
	for(int i=0; i<size; i++){

		element_init_same_as(ciphertext_result[i], mul_result[0][i]);
		element_set(ciphertext_result[i], mul_result[0][i]);

		for(int j=0; j<noOfLearners-1; j++){

			b->add(PK, ciphertext_result[i], mul_result[j+1][i], ciphertext_result[i]);

		}

	}*/




}




std::vector<std::string> pack_params(const std::vector<unsigned int>& params){

	int params_size = params.size();
	

	int packed_params_size = ceil((float)params.size()/(float)nums_to_pack);

	std::vector<std::string> packed_params(packed_params_size, "");

	int count_params = 0;
	int count_packed = 0;


	while(count_params < params_size){

		for(int i=0; i<nums_to_pack; i++){

			std::string bin_rep = "";


			if(count_params < params_size){

				bin_rep = std::bitset<num_rep_bits>(params[count_params]).to_string();

			}
			else{

				bin_rep = std::bitset<num_rep_bits>(0).to_string();
			}

			packed_params[count_packed] = bin_rep.append(packed_params[count_packed]);
			count_params+=1;

		}

		count_packed+=1;

	}


	for(int i=0; i<packed_params.size(); i++){

		std::stringstream sstream(packed_params[i]);
		std::string output="";


		while(sstream.good()){

			//std::cout<<"good"<<std::endl;

			std::bitset<8> bits;
			sstream >> bits;
			char c = char(bits.to_ulong());
			output += c;

    	}

    	packed_params[i] = output;

	}


	return packed_params;


}



std::vector<unsigned int> unpack_params(std::vector<std::string>& packed_params){

	int packed_params_size = packed_params.size();

	std::vector<unsigned int> params;

	int count_params = 0;
	int count_packed = 0;


	while(count_packed < packed_params_size){

		std::string bin_rep = packed_params[count_packed];

		//std::cout<<"bin_rep: "<<bin_rep<<std::endl;

		int start = bin_rep.length() - num_rep_bits;

		std::cout<<"start: "<<std::to_string(start)<<std::endl;


        for(int i=0; i<nums_to_pack; i++){

        	if (count_params < noOfParams){

        		unsigned int val = (unsigned int)(std::bitset<num_rep_bits>(bin_rep.substr(start, num_rep_bits)).to_ulong());
        		std::cout<<bin_rep.substr(start, num_rep_bits)<<std::endl;
        		std::cout<<std::to_string(val)<<std::endl;


        		params.push_back(val);

        	}

        	else{
        		break;
        	}

        	start = start - num_rep_bits;

        	if(start < 0){
                start = 0;
        	}

        	count_params+=1;

        }

        count_packed+=1;

        //break;



	}



	return params;


}





