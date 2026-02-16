#pragma once
#include "mode2_circuit.h"  // Include this FIRST
#include "types.h"
#include "algebra/fp_p256.h" 
#include <stdexcept>

namespace zkp {
struct Mode2Prover {
    Mode2Circuit& c;
    using Field  = proofs::Fp256<>;
    using Elt = Field::Elt;
    bool prove(Elt pub, Elt priv, uint8_t* proof_out, size_t proof_size);
};

// ADD THESE DECLARATIONS:
Proof generate_proof(const ProofInput& input, PublicInputs& pub);
} // namespace zkp

