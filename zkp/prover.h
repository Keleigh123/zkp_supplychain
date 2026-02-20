#pragma once

#include "mode2_circuit.h"
#include "types.h"
#include "algebra/fp_p256.h"
#include <cstddef>
#include <cstdint>

namespace zkp {

struct Mode2Prover {
    Mode2Circuit& c;

    using Field = proofs::Fp256<>;
    using Elt   = Field::Elt;

    size_t last_proof_len_ = 0;

    bool prove(Elt pub, Elt priv, uint8_t* proof_out, size_t proof_size);
};

Proof generate_proof(const ProofInput& input, PublicInputs& pub);

} // namespace zkp
