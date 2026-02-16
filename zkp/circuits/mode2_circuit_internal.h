#pragma once

#include "algebra/fp.h"
#include "circuit.h" 
#include "logic.h"
#include "algebra/fp_p256.h" 

namespace zkp::internal {

class Mode2Circuit final : public proofs::Circuit<proofs::Fp256<>> {
public:

    Mode2Circuit();
    // Remove this line - it's causing the issue:
    // const proofs::Fp<256>& F; 
    
    // Add proper field access
    // const proofs::Fp<256>& field() const { return Circuit<proofs::Fp<256>>::F; }
};

} // namespace zkp::internal
