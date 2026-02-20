#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

#include "sumcheck/circuit.h"
#include "algebra/fp_p256.h"

namespace zkp::internal {

// IMPORTANT:
// proofs::Circuit<Field> is just a POD struct (no field context).
// So we keep our own Field instance for canonicalize / constants,
// but the base Circuit does NOT store it.
class Mode2Circuit final : public proofs::Circuit<proofs::Fp256<>> {
public:
  using Field = proofs::Fp256<>;

  // Used only for building constants (quad coefficients) safely.
  Field field_;

  Mode2Circuit();

  const Field& field() const { return field_; }
  Field& field_mut() { return field_; }
};

}  // namespace zkp::internal
