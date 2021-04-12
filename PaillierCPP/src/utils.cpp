#include "utils.h"




paillier_plaintext_t** createParamsArray(){

	paillier_plaintext_t** weights = (paillier_plaintext_t**) malloc(noOfParams * sizeof(paillier_plaintext_t*));

	srand(time(NULL));

	//#pragma omp parallel for
    for(int i=0; i<noOfParams; i++){
    	weights[i] = paillier_plaintext_from_ui(rand());
    }

	return weights;

}


paillier_plaintext_t**  paramsArrayfromVector(std::vector<std::string> params){


	paillier_plaintext_t** weights = (paillier_plaintext_t**) malloc(params.size() * sizeof(paillier_plaintext_t*));


	//#pragma omp parallel for
    for(int i=0; i<params.size(); i++){

    	weights[i] = paillier_plaintext_from_str( const_cast<char*>(params[i].c_str()));

    }

	return weights;


}


void initializeLearners(paillier_plaintext_t*** learners_plaintext){


	for(int i=0; i<totalLearners; i++){

		learners_plaintext[i] = createParamsArray();

	}

}

paillier_ciphertext_t** encryptParams(paillier_plaintext_t** plaintext_arr, int size, paillier_pubkey_t* public_key){

	paillier_ciphertext_t** ciphertext_arr = (paillier_ciphertext_t**) malloc(size * sizeof(paillier_ciphertext_t*));

	
	for(int i=0; i<size; i++){

		ciphertext_arr[i] = paillier_enc(NULL, public_key, plaintext_arr[i], get_rand);

	}

	return ciphertext_arr;

}


paillier_plaintext_t** decryptParams(paillier_ciphertext_t** ciphertext_arr, int size, paillier_pubkey_t* public_key, paillier_prvkey_t* private_key){


	paillier_plaintext_t** plaintext_arr = (paillier_plaintext_t**) malloc(size * sizeof(paillier_plaintext_t*));

	#pragma omp parallel for 
	for(int i=0; i<size; i++){

		plaintext_arr[i] = paillier_dec(NULL, public_key, private_key, ciphertext_arr[i]);

	}

	return plaintext_arr;

}


void calculate_homomorphic_sum(paillier_ciphertext_t** ciphertext_result, paillier_ciphertext_t*** ciphertext_arr, int size, int noOfLearners, paillier_pubkey_t* public_key){

	#pragma omp parallel for 
	for(int i=0; i<size; i++){

		ciphertext_result[i] = ciphertext_arr[0][i];

		for(int j=0; j<noOfLearners-1; j++){

			paillier_mul(public_key, ciphertext_result[i], ciphertext_result[i], ciphertext_arr[j+1][i]);

		}

	}

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





/*

std::map<std::string, std::vector<float>>* read_learners__params_npz(){

	std::map<std::string, std::vector<float>>* learners_plaintext = new std::map<std::string, std::vector<float>>();



	for (int i=0; i<totalLearners; i++){

		cnpy::npz_t params_npz = cnpy::npz_load(learner_params_folder + learner_params_files[i]);

		std::vector<float> params;



		for (auto& x: params_npz) {

			cnpy::NpyArray arr = x.second;

			float* loaded_data = arr.data<float>();

			for (int j = 0; j < arr.shape[0]; j++) {
    			params.push_back(loaded_data[j]);
  			}

		}

		/////////////////////remove this ////////////////////////////////

		params.resize(100);



		/////////////////////remove this ////////////////////////////////




		learners_plaintext->insert(std::pair<std::string, std::vector<float>>("l"+std::to_string(i+1),params) );



	}


	return learners_plaintext;


}




std::map<std::string, std::vector<unsigned int>>* generate_learners_params(){

	std::map<std::string, std::vector<unsigned int>>* learners_plaintext = new std::map<std::string, std::vector<unsigned int>>();

	 srand (time(NULL));



	for (int i=0; i<totalLearners; i++){

		std::vector<unsigned int> params;

		for (int j = 0; j < noOfParams; j++) {
    			params.push_back(rand());
  		}

		learners_plaintext->insert(std::pair<std::string, std::vector<unsigned int>>("l"+std::to_string(i+1),params) );

	}


	return learners_plaintext;


}


std::map<std::string, paillier_plaintext_t**>* convert_to_paillier_plaintext(std::map<std::string, std::vector<unsigned int>>* learners_params){

	std::map<std::string, paillier_plaintext_t**>* learners_params_pt = new std::map<std::string, paillier_plaintext_t**>();


	for (auto const& x : *learners_params)
	{

		std::vector<unsigned int> params_vec = x.second;

		paillier_plaintext_t** params_pt = (paillier_plaintext_t**) malloc(params_vec.size() * sizeof(paillier_plaintext_t*));

		 for(int i=0; i<params_vec.size(); i++){

		 	params_pt[i] = paillier_plaintext_from_ui(i);
    	}


    	learners_params_pt->insert(std::pair<std::string, paillier_plaintext_t**>(x.first,params_pt) );

	}


	return learners_params_pt;

}




std::map<std::string, paillier_ciphertext_t**>* encrypt_learners_params(std::map<std::string, paillier_plaintext_t**>* learners_params_pt){


	std::map<std::string, paillier_ciphertext_t**>* learners_params_ct = new std::map<std::string, paillier_ciphertext_t**>();

	//std::map<std::string, paillier_ciphertext_t**>::iterator it = learners_params_pt->begin();


	//#pragma omp parallel for
	for(std::map<std::string, paillier_plaintext_t**>::iterator it = std::begin(*learners_params_pt); it != std::end(*learners_params_pt); it++){
     //construct the distance matrix...
	}









	while(it != learners_params_pt->end()){

		paillier_ciphertext_t** params_ct = encryptParams(it->second, noOfParams);

		learners_params_ct->insert(std::pair<std::string, paillier_ciphertext_t**>(it->first,params_ct));
			
		it++;

	}


	
	for (auto const& x : *learners_params_pt)
	{

		paillier_ciphertext_t** params_ct = encryptParams(x.second, noOfParams);

    	learners_params_ct->insert(std::pair<std::string, paillier_ciphertext_t**>(x.first,params_ct));

	}


	return learners_params_ct;

}


std::map<std::string, paillier_plaintext_t**>* decrypt_learners_params(std::map<std::string, paillier_ciphertext_t**>* learners_params_ct){


	std::map<std::string, paillier_plaintext_t**>* learners_params_pt = new std::map<std::string, paillier_plaintext_t**>();


	for (auto const& x : *learners_params_ct)
	{

		
		paillier_plaintext_t** params_pt = decryptParams(x.second, noOfParams);

    	learners_params_pt->insert(std::pair<std::string, paillier_plaintext_t**>(x.first,params_pt) );

	}


	return learners_params_pt;

}



paillier_ciphertext_t** calculate_homomorphic_sum(std::map<std::string, paillier_ciphertext_t**>* learners_params_ct){


	paillier_ciphertext_t** HE_sum = (paillier_ciphertext_t**) malloc(noOfParams * sizeof(paillier_ciphertext_t*));

	std::map<std::string, paillier_ciphertext_t**>::iterator it = learners_params_ct->begin();

	//#pragma omp parallel for
	for(int i=0; i<noOfParams; i++){

		HE_sum[i] = it->second[i];
		it++;

		while(it != learners_params_ct->end()){

			paillier_mul(public_key, HE_sum[i], HE_sum[i], it->second[i]);
			it++;

		}

		it = learners_params_ct->begin();

	}


	return HE_sum;

}



*/




