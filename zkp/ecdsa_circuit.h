#pragma once
#include <memory>

#include "sumcheck/circuit.h"
#include "ec/p256.h"   // <-- add this

namespace zkp {
using Field = proofs::Fp256Base;
std::unique_ptr<proofs::Circuit<Field>> build_ecdsa_verify_circuit();
}