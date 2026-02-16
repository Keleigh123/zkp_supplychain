#pragma once
#include <vector>
#include <cstdint>
#include "types.h"
#include "mode2_circuit.h"        // FULL definition needed
#include "algebra/fp_p256.h" 

namespace zkp {
    // NO forward declarations needed - mode2_circuit.h provides full Mode2Circuit

    bool run_verifier(const std::vector<uint8_t>& pub, const std::vector<uint8_t>& proof);
    bool verify_proof(const Proof& proof, const PublicInputs& pub);

    struct Mode2Verifier {
        Mode2Circuit& c;  // Complete type from mode2_circuit.h
        
        using Field  = proofs::Fp256<>;
        using Elt = Field::Elt;
        bool verify(Elt pub, const uint8_t* proof_in, size_t proof_len);
    };
}
