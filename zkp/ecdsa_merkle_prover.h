#pragma once
#include "types.h"

namespace zkp {

Proof generate_ecdsa_merkle_proof(const EcdsaMerkleProofInput& in, PublicInputs& pub);

} // namespace zkp