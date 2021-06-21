#include "utils.h"
#include "palisade.h"

using namespace std;
using namespace lbcrypto;
using namespace std::chrono;

int main() {
	string scheme = "ckks";
 
	//generates the cryptocontext and necessary keys
	genCryptoContextAndKeyGen(scheme);

	cout << "\n" << endl;

	//learner data and number of parameters used per learner
	vector<cnpy::npz_t> learners =
      loadLearners(14, "/Users/tanmay.ghai/palisade_shelfi_interface/learners_flattened/learner1_");
      //{"arr_0",  "arr_1",  "arr_2",  "arr_3", "arr_4", 
      //      "arr_5",  "arr_6",  "arr_7",  "arr_8", "arr_9", 
      //      "arr_10", "arr_11", "arr_12", "arr_13"}
       vector<string> arrays = {"arr_0", "arr_1", "arr_2", "arr_3","arr_4", "arr_5", "arr_6"};

    cout << "\n" << endl;

    //encryption api, serializes ciphertexts for pwa computation
    encryption(scheme, learners, arrays);

    cout << "\n" << endl;

    //computes pwa over encrypted model, serializes and stores result for decryption
    computeWeightedAverage(scheme, 1000, learners, arrays);

     cout << "\n" << endl;

	//decrypts pwa result
     decryption();

}