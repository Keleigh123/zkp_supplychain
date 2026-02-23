#pragma once
#include "types.h"

namespace zkp {

Proof generate_ecdsa_proof(const EcdsaProofInput& in, PublicInputs& pub);

} // namespace zkp