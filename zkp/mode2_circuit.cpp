#include "mode2_circuit.h"

// ---- INTERNAL CIRCUIT ----
#include "circuits/mode2_circuit_internal.h"

// ---- Longfellow ZK ----
#include "zk_proof.h"
#include "zk_prover.h"
#include "zk_verifier.h"
#include "algebra/fp_p256.h" 
#include <vector>
#include "prover.h"
#include "verifier.h"


using namespace proofs; 

namespace zkp {

using InternalCircuit = zkp::internal::Mode2Circuit;
using Field  = proofs::Fp256<>;
using Elt    = Field::Elt;
using ProofT = proofs::ZkProof<Field>;

// ---------- helpers ----------

static bool bytes_to_elts(
    const uint8_t* in,
    size_t len,
    std::vector<Elt>& out
) {
    if (len % Field::kBytes != 0) return false;

    Field field;  // ✅ create instance

    size_t n = len / Field::kBytes;
    out.resize(n);

    for (size_t i = 0; i < n; i++) {
        auto v = field.of_bytes_field(in + i * Field::kBytes);
        if (!v) return false;
        out[i] = *v;
    }
    return true;
}



// ---------- lifecycle ----------

Mode2Circuit* create_mode2_circuit() {
  return new Mode2Circuit{};
}

void destroy_mode2_circuit(Mode2Circuit* c) {
  delete c;
}

Mode2Prover* create_mode2_prover(Mode2Circuit* c) {
  return new Mode2Prover{*c};
}

void destroy_mode2_prover(Mode2Prover* p) {
  delete p;
}

Mode2Verifier* create_mode2_verifier(Mode2Circuit* c) {
  return new Mode2Verifier{*c};
}

void destroy_mode2_verifier(Mode2Verifier* v) {
  delete v;
}

// ---------- prove ----------

bool mode2_prove(Mode2Prover* prover, const uint8_t* public_inputs, size_t public_len,
                     const uint8_t* private_inputs, size_t private_len, std::vector<uint8_t>& proof_out) {
//   const Field& F = prover->c.circuit.field();
if (public_len != Field::kBytes || private_len != Field::kBytes) {
    return false; // wrong length, don't even try
}

  std::vector<Elt> pub, priv;
  
  if (!bytes_to_elts(public_inputs, public_len, pub)) return false;
  if (!bytes_to_elts(private_inputs, private_len, priv)) return false;
  
  if (pub.size() != 1 || priv.size() != 1) return false;
  
  // USE PROVER CLASS DIRECTLY:
  //return prover->prove(pub[0], priv[0], proof_out.data(), proof_out.size());
  // Allocate a reasonable max
std::vector<uint8_t> buf(65536);
bool ok = prover->prove(pub[0], priv[0], buf.data(), buf.size());
if (!ok) return false;

// Shrink to actual proof size; you may need prove() to tell you the length,
// but if it doesn’t, you should have ZkProof::write() size available
// For now, assume zkpr.write() was bounded to buf.size()
proof_out.assign(buf.begin(), buf.end());
return true;
}
// ---------- verify ----------

bool mode2_verify(Mode2Verifier* verifier, const uint8_t* public_inputs, size_t public_len,
                      const uint8_t* proof_in, size_t proof_len) {
//   const Field& F = verifier->c.circuit.field();

  std::vector<Elt> pub;
  
  if (!bytes_to_elts(public_inputs, public_len, pub)) return false;
  if (pub.size() != 1) return false;
  
  // USE VERIFIER CLASS DIRECTLY:
  return verifier->verify(pub[0], proof_in, proof_len);
}

bool run_prover(
    const std::vector<uint8_t>& pub_input,
    const std::vector<uint8_t>& priv_input, 
    std::vector<uint8_t>& proof_out
) {
    Mode2Circuit* c = create_mode2_circuit();
    Mode2Prover* p = create_mode2_prover(c);
    
    bool ok = mode2_prove(
        p, 
        pub_input.data(), pub_input.size(),
        priv_input.data(), priv_input.size(),
        proof_out
    );
    
    destroy_mode2_prover(p);
    destroy_mode2_circuit(c);
    return ok;
}
} // namespace zkp
