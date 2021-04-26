
#include "palisade.h"
#include <iostream>
#include <fstream>
#include <map>
#include <time.h>
#include <stdlib.h>
#include "csvstream.h"
#include "../cnpy.h"
#include "pwa_utils.h"
#include <sstream>
#include <chrono>

using namespace std;
using namespace lbcrypto;
using namespace std::chrono;

int main() {
  int plaintextModulus = 65537;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 2;
  usint batchSize = 8192;

  // Instantiate the BGVrns crypto context
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV,
          batchSize);

  // enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  // Initialize Public Key Containers
  LPKeyPair<DCRTPoly> kp1;

  LPKeyPair<DCRTPoly> kpMultiparty;

  kp1 = cc->KeyGen();
  cc->EvalMultKeyGen(kp1.secretKey);

  int numLearners = 10;
  float training_samples = 1000;

  cout << "Benchmarking BGVrns.." << endl;

  vector<cnpy::npz_t> learners = loadLearners(numLearners);
  vector<map<string, Plaintext>> maps;
  vector<string> arrays = {"arr_0", "arr_1", "arr_2", "arr_3",
                           "arr_4", "arr_5", "arr_6"};

  for (cnpy::npz_t learner : learners) {
    map<string, Plaintext> mappings;

    for (string idx : arrays) {
      cnpy::NpyArray arr = learner[idx];

      // cout << idx << ", " << arr.shape << endl;

      float* loaded_data = arr.data<float>();

      vector<float> curr;

      for (int i = 0; i < arr.shape[0]; i++) {
        curr.push_back(loaded_data[i]);
      }

      vector<int64_t> curr2;
      for (int i = 0; i < curr.size(); i++) {
        curr2[i] = (int64_t)curr[i];
      }

      Plaintext p = cc->MakePackedPlaintext(curr2);

      mappings[idx] = p;
    }
    maps.push_back(mappings);
  }

  cout << "Encrypting.." << endl;

  auto start = high_resolution_clock::now();

  map<int, vector<Ciphertext<DCRTPoly>>> ciphertexts =
      encryptLearnerData(cc, kp1, maps);

  auto stop = high_resolution_clock::now();
  auto duration = stop - start;
  cout << "Time taken by a learner to encrypt parameters: "
       << duration.count() / learners.size() << " milliseconds" << endl;

  cout << "Weighted Average.." << endl;

  start = high_resolution_clock::now();

  vector<Ciphertext<DCRTPoly>> c0 = ciphertexts[0];

  cout << (sizeof(std::vector<DCRTPoly>) + (sizeof(DCRTPoly) * c0.size())) * 8
       << endl;

  long weight = training_samples / (learners.size() * training_samples);

  vector<int64_t> weights(training_samples);
  std::fill(weights.begin(), weights.end(), weight);
  auto pw = cc->MakePackedPlaintext(weights);

  auto pwa = cc->EvalMult(pw, c0[0]);

  for (int i = 0; i < arrays.size(); i++) {
    for (int j = 0; j < learners.size(); j++) {
      if (i == 0 && j == 0) {
      } else {
        // cout << i << ", " << j << endl;
        vector<Ciphertext<DCRTPoly>> c = ciphertexts[j];
        cc->EvalAdd(pwa, cc->EvalMult(pw, c[i]));
      }
    }
  }

  stop = high_resolution_clock::now();
  duration = stop - start;
  cout << "Time taken to compute weighted average of "
          "parameters of "
       << learners.size() << " learners: " << duration.count()
       << " milliseconds" << endl;

  cout << "(4) Decrypting.." << endl;

  start = high_resolution_clock::now();

  Plaintext decryptResult = decryptPwa(cc, kp1, pwa);

  duration = start - stop;
  cout << "time taken (s): " << duration.count() * 10 << " milliseconds"
       << endl;
}