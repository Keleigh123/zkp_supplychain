#include "verifier.h"
#include "mode2_circuit.h"
#include "zk_proof.h"
#include "zk_prover.h"
#include "zk_verifier.h"
#include "algebra/fp_p256.h" 
#include <vector>
#include "algebra/fp2.h"
#include "algebra/convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/readbuffer.h"


using namespace proofs;

namespace zkp {

using Field   = proofs::Fp256<>;
using Elt     = Field::Elt;
using Field2  = proofs::Fp2<Field>;
using FftExtConvolutionFactory = proofs::FFTExtConvolutionFactory<Field, Field2>;
using RSFactory = proofs::ReedSolomonFactory<Field, FftExtConvolutionFactory>;

constexpr size_t kLigeroRate = 2;
constexpr size_t kLigeroNreq = 1;  // NOT 6
static constexpr size_t kVersion    = 4;

bool Mode2Verifier::verify(Elt pub, const uint8_t* proof_in, size_t proof_len) {
  const Field base;
    const Field2 base2(base);

    // Hardcoded or precomputed root for Fp2:
Field2::Elt omega{
    base.of_string("112649224146410281873500457609690258373018840430489408729223714171582664680802"),
    base.of_string("84087994358540907695740461427818660560182168997182378749313018254450460212908")
};
uint64_t root_order = 1ull << 31;

FftExtConvolutionFactory fft(base, base2, omega, root_order);
RSFactory rsf(fft, base);

    // Reconstruct proof from bytes
    proofs::ZkProof<Field> zkpv(c.circuit, kLigeroRate, kLigeroNreq);
    proofs::ReadBuffer rb(proof_in, proof_len);
    if (!zkpv.read(rb, base)) return false;

    // Build public input Dense<Field>
    proofs::Dense<Field> pub_dense(1, c.circuit.npub_in);
    proofs::DenseFiller<Field> pf(pub_dense);
    pf.push_back(pub);

    proofs::Transcript tv(reinterpret_cast<const uint8_t*>("mode2"), 5, kVersion);
    proofs::ZkVerifier<Field, RSFactory> verifier(c.circuit, rsf,
                                                  kLigeroRate, kLigeroNreq, base);
    verifier.recv_commitment(zkpv, tv);
    return verifier.verify(zkpv, pub_dense, tv);
}



bool run_verifier(const std::vector<uint8_t>& pub, const std::vector<uint8_t>& proof) {
    if (pub.empty() || proof.empty()) return false;

    Mode2Circuit* c = create_mode2_circuit();
    Mode2Verifier* v = create_mode2_verifier(c);

    bool ok = mode2_verify(v, pub.data(), pub.size(), proof.data(), proof.size());
    destroy_mode2_verifier(v);
    destroy_mode2_circuit(c);
    return ok;
}

bool verify_proof(const Proof& proof, const PublicInputs& pub) {
    return run_verifier(pub.data, proof.data);
}

} // namespace zkp
