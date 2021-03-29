#include "palisade.h"
#include <map>
#include "../cnpy.h"

// utility methods for pwa calculations in pwa_bgvrns & pwa_ckks

using namespace std;
using namespace lbcrypto;
using namespace std::chrono;

vector<cnpy::npz_t> loadLearners(int numLearners) {
  vector<cnpy::npz_t> learners;
  for (int i = 0; i < numLearners; i++) {
    cnpy::npz_t l = cnpy::npz_load(
        "/Users/tanmay.ghai/Desktop/palisade-development/src/pke/examples/"
        "test_data/learners_flattened/learner1_" +
        std::to_string(i) + ".npz");

    learners.push_back(l);
  }
  return learners;
}

map<int, vector<Ciphertext<DCRTPoly>>> encryptLearnerData(
    CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kp,
    vector<map<string, Plaintext>> maps) {
  map<int, vector<Ciphertext<DCRTPoly>>> ciphertexts;

  for (int i = 0; i < maps.size(); i++) {
    map<string, Plaintext> m = maps[i];
    map<string, Plaintext>::iterator it;

    vector<Ciphertext<DCRTPoly>> curr;

    for (it = m.begin(); it != m.end(); it++) {
      Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, it->second);
      curr.push_back(ciphertext);
    }
    ciphertexts[i] = curr;
  }

  return ciphertexts;
}

Plaintext decryptPwa(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kp,
                     Ciphertext<DCRTPoly> pwa) {
  Plaintext decryptResult;
  cc->Decrypt(kp.secretKey, pwa, &decryptResult);
  return decryptResult;
}
