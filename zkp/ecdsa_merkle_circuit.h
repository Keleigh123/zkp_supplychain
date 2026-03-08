#pragma once
#include <memory>
#include "sumcheck/circuit.h"
#include "ec/p256.h"

namespace zkp {
using Field = proofs::Fp256Base;
std::unique_ptr<proofs::Circuit<Field>> build_ecdsa_merkle_verify_circuit();
}