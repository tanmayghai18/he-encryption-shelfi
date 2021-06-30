#include "utils.h"
#include "palisade.h"
#include <random>
#include <string>

using namespace std;
using namespace lbcrypto;
using namespace std::chrono;


void generateRandomData(vector<vector<double>>& learner_Data, int rows, int cols){

    double lower_bound = 0;
    double upper_bound = 100;
    std::uniform_real_distribution<double> unif(lower_bound,upper_bound);
    std::default_random_engine re;
    //double a_random_double = unif(re);

    for(int i=0; i<rows; i++){

        vector<double> arr;

        for(int j=0; j<cols; j++){

            arr.push_back(unif(re));

            // arr.push_back(i);

        }

        learner_Data.push_back(arr);


    }


}


int main() {
	string scheme = "ckks";
 
	//generates the cryptocontext and necessary keys
    //run if required for the first time
    //keys are stored in CryptoParams folder
	//genCryptoContextAndKeyGen(scheme);


    //geneting random data for testing.
    vector<vector<double>> learner_Data;

    // 10 layers each with 20 parameters
    generateRandomData(learner_Data, 10, 20);

    cout<<"Learner Data: "<<endl;

    cout<<learner_Data<<endl<<endl<<endl;

    string enc_result = encryption(scheme, learner_Data);

    vector<string> learners_Data;

    cout<<"Encrypting"<<endl;

    learners_Data.push_back(enc_result);
    learners_Data.push_back(enc_result);
    learners_Data.push_back(enc_result);

    vector<float> scalingFactors;

    scalingFactors.push_back(0.5);
    scalingFactors.push_back(0.3);
    scalingFactors.push_back(0.5);

    cout<<"Computing 0.5*L + 0.3*L + 0.5*L"<<endl;


    string pwa_result = computeWeightedAverage(scheme, learners_Data, scalingFactors);

    vector<int> data_dimensions(learner_Data.size(),20);

    cout<<"Decrypting"<<endl;

    vector<vector<double>> pwa_res_pt = decryption(scheme, pwa_result, data_dimensions);


    cout<<"Result:"<<endl;

    cout<<pwa_res_pt<<endl<<endl<<endl<<endl;




}