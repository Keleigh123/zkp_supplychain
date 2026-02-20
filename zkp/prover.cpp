#include "prover.h"
#include "types.h"
#include "mode2_circuit.h"
#include "zk_proof.h"
#include "zk_prover.h"
#include "algebra/fp_p256.h"

#include <vector>
#include <stdexcept>
#include <algorithm>
#include <iostream>
#include <iomanip>

#include "../utils/crypto_utils.h"
#include "random/transcript.h"
#include "arrays/dense.h"
#include "algebra/fp2.h"
#include "algebra/convolution.h"
#include "algebra/reed_solomon.h"
#include "random/secure_random_engine.h"

using namespace proofs;

namespace zkp {

using Field  = proofs::Fp256<>;
using Elt    = Field::Elt;
using Field2 = proofs::Fp2<Field>;
using FftExtConvolutionFactory = proofs::FFTExtConvolutionFactory<Field, Field2>;
using RSFactory = proofs::ReedSolomonFactory<Field, FftExtConvolutionFactory>;

constexpr size_t kLigeroRate = 2;
constexpr size_t kLigeroNreq = 1;
static constexpr size_t kVersion = 4;

bool Mode2Prover::prove(Elt pub, Elt priv, uint8_t* proof_out, size_t proof_size) {
    printf("Circuit: ninputs=%zu, npub_in=%zu, nl=%zu\n",
           c.circuit.ninputs, c.circuit.npub_in, c.circuit.nl);

    // CRITICAL: use base-class field via accessor
    const Field& base = c.circuit.field();

  std::cerr << "Circuit field addr: " << (const void*)&c.circuit.field() << "\n";


    const Field2 base2(base);

    Field2::Elt omega{
        base.of_string("112649224146410281873500457609690258373018840430489408729223714171582664680802"),
        base.of_string("84087994358540907695740461427818660560182168997182378749313018254450460212908")
    };

    uint64_t root_order = 1ull << 31;

    FftExtConvolutionFactory fft(base, base2, omega, root_order);
    RSFactory rsf(fft, base);

    size_t ninputs = c.circuit.ninputs;

    proofs::Dense<Field> W(1, ninputs);
    proofs::DenseFiller<Field> filler(W);
    filler.push_back(pub);
    filler.push_back(priv);

    while (filler.size() < ninputs) filler.push_back(base.zero());

    if (filler.size() != ninputs) {
        throw std::runtime_error("witness size != circuit.ninputs");
    }

    proofs::ZkProof<Field> zkpr(c.circuit, kLigeroRate, kLigeroNreq);
    proofs::Transcript tp(reinterpret_cast<const uint8_t*>("mode2"), 5, kVersion);
    proofs::SecureRandomEngine rng;

    proofs::ZkProver<Field, RSFactory> prover(c.circuit, base, rsf);

    prover.commit(zkpr, W, tp, rng);

    bool ok = prover.prove(zkpr, W, tp);
    if (!ok) return false;

    std::vector<uint8_t> bytes;
    zkpr.write(bytes, base);

    last_proof_len_ = bytes.size();

    if (bytes.size() > proof_size) return false;
    std::copy(bytes.begin(), bytes.end(), proof_out);
    return true;
}

Proof generate_proof(const ProofInput& input, PublicInputs& pub) {
    std::vector<uint8_t> message;

    message.insert(message.end(), input.supplierPK.begin(), input.supplierPK.end());

    std::cout << "supplierPK: ";
    for (auto b : input.supplierPK)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << std::dec << "\n";

    uint64_t ts = input.timestamp;
    for (int i = 0; i < 8; i++) message.push_back((ts >> (8 * i)) & 0xff);
    std::cout << "timestamp: " << ts << "\n";

    message.insert(message.end(), input.nonce.begin(), input.nonce.end());

    std::cout << "nonce: ";
    for (auto b : input.nonce)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << std::dec << "\n";

    std::vector<uint8_t> digest = sha256(message);

    std::cout << "digest: ";
    for (auto b : digest)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << std::dec << "\n";

    if (digest.size() != Field::kBytes)
        throw std::runtime_error("digest size mismatch");

    std::vector<uint8_t> pub_input  = digest;
    std::vector<uint8_t> priv_input = digest;

    std::vector<uint8_t> proof_data;
    if (!run_prover(pub_input, priv_input, proof_data))
        throw std::runtime_error("proof failed");

    pub.data = pub_input;
    return { std::move(proof_data) };
}

} // namespace zkp
