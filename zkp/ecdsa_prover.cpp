#include "ecdsa_prover.h"
#include "ecdsa_circuit.h"

#include "arrays/dense.h"
#include "circuits/ecdsa/verify_witness.h"
#include "random/transcript.h"
#include "random/secure_random_engine.h"
#include "algebra/fp2.h"
#include "algebra/convolution.h"
#include "algebra/reed_solomon.h"
#include "ec/p256.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"

#include "field_parse.h"
#include <vector>
#include <stdexcept>
#include <algorithm>

namespace zkp {

using Field = proofs::Fp256Base;
using Elt   = Field::Elt;
using Nat   = proofs::Fp256Base::N;

using Field2 = proofs::Fp2<Field>;
using FftExtConvolutionFactory = proofs::FFTExtConvolutionFactory<Field, Field2>;
using RSFactory = proofs::ReedSolomonFactory<Field, FftExtConvolutionFactory>;

constexpr size_t kLigeroRate = 2;
constexpr size_t kLigeroNreq = 1;
static constexpr size_t kVersion = 4;

Proof generate_ecdsa_proof(const EcdsaProofInput& in, PublicInputs& pub) {
  auto circuit = build_ecdsa_verify_circuit();

  // Parse pk as base-field elts
  Elt pkx_elt = zkp::base_elt_from_32_be_strict(in.pkx_32, "pkx");
  Elt pky_elt = zkp::base_elt_from_32_be_strict(in.pky_32, "pky");

  // Parse r,s,e as BASE Nats for VerifyWitness3 (matches zk_test)
  Nat r = zkp::rs_as_base_nat_from_32_be_strict(in.r_32, "r");
  Nat s = zkp::rs_as_base_nat_from_32_be_strict(in.s_32, "s");
  Nat e_nat = zkp::e_as_base_nat_from_digest_mod_n(in.e_32);

  // IMPORTANT: witness uses to_montgomery(e_nat) (exactly like zk_test.cc)
  Elt e_wire = proofs::p256_base.to_montgomery(e_nat);

  // Witness vector (full width = circuit->ninputs)
  proofs::Dense<Field> W(1, circuit->ninputs);
  proofs::DenseFiller<Field> filler(W);

  using Verw = proofs::VerifyWitness3<proofs::P256, proofs::Fp256Scalar>;
  Verw vw(proofs::p256_scalar, proofs::p256);

  if (!vw.compute_witness(pkx_elt, pky_elt, e_nat, r, s)) {
    throw std::runtime_error("ECDSA witness computation failed (pk/sig not consistent with e mod n)");
  }

  // EXACT order from zk_test.cc:
  filler.push_back(proofs::p256_base.one());
  filler.push_back(pkx_elt);
  filler.push_back(pky_elt);
  filler.push_back(e_wire);
  vw.fill_witness(filler);

  // Public input: ONLY the leading "1" (because mkcircuit(1))
  proofs::Dense<Field> Pub(1, circuit->npub_in);
  proofs::DenseFiller<Field> pubfill(Pub);
  pubfill.push_back(proofs::p256_base.one());

  // Ligero setup
  Field2 base2(proofs::p256_base);
  Field2::Elt omega{
      proofs::p256_base.of_string("0xf90d338ebd84f5665cfc85c67990e3379fc9563b382a4a4c985a65324b242562"),
      proofs::p256_base.of_string("0xb9e81e42bc97cc4da04fc2e20106e34084738a6474d232c6dbf4174f60a43eac")
  };
  uint64_t root_order = 1ull << 31;

  FftExtConvolutionFactory fft(proofs::p256_base, base2, omega, root_order);
  RSFactory rsf(fft, proofs::p256_base);

  proofs::ZkProof<Field> zkpr(*circuit, kLigeroRate, kLigeroNreq);
  proofs::Transcript tp(reinterpret_cast<const uint8_t*>("ecdsa"), 5, kVersion);
  proofs::SecureRandomEngine rng;

  proofs::ZkProver<Field, RSFactory> prover(*circuit, proofs::p256_base, rsf);

  prover.commit(zkpr, W, tp, rng);
  if (!prover.prove(zkpr, W, tp)) {
    throw std::runtime_error("prove failed");
  }

  std::vector<uint8_t> proof_bytes;
  zkpr.write(proof_bytes, proofs::p256_base);

  // Serialize public inputs (ONLY 1 elt = "1")
  pub.data.resize(32);
  proofs::p256_base.to_bytes_field(pub.data.data(), proofs::p256_base.one());

  return { std::move(proof_bytes) };
}

} // namespace zkp