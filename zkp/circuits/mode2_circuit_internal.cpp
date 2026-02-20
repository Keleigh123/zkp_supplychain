#include "mode2_circuit_internal.h"
#include "sumcheck/quad.h"

#include <iostream>
#include <memory>
#include <cstring>

namespace zkp::internal {

using Field = proofs::Fp256<>;

Mode2Circuit::Mode2Circuit() {
  // =========================
  // FULL Circuit initialization
  // =========================

  // We are building a 1-layer circuit with 2 input wires:
  // wire0 = public, wire1 = private
  // Constraint: wire0 - wire1 == 0 (assert zero)

  // Outputs/copies metadata (MUST be initialized!)
  nv = 1;     // number of outputs for one copy (use 1 for assert-zero circuits)
  logv = 0;   // log2(nv) style variable count; 1 output -> logv = 0

  nc = 1;     // number of copies
  logc = 0;   // log2(nc); 1 copy -> logc = 0

  nl = 1;     // number of layers

  ninputs = 2;
  npub_in = 1;

  // All inputs are "in the field" (no subfield optimization here)
  subfield_boundary = ninputs;

  // Give the circuit id a deterministic value (doesn't need to be fancy)
  std::memset(id, 0, sizeof(id));
  // Optional: set first byte so it's not all-zero if you prefer:
  id[0] = 0x02;

  // =========================
  // Build layer 0
  // =========================
  proofs::Layer<Field> layer;
  layer.logw = 1;
  layer.nw = (1u << layer.logw);  // 2 wires

  // Build a quad with 2 terms:
  // +1 * W0  + (-1) * W1  == 0
  auto q = std::make_unique<proofs::Quad<Field>>(2);

  // term0: +1 * wire0
  q->c_[0].g    = proofs::Quad<Field>::quad_corner_t(0);
  q->c_[0].h[0] = proofs::Quad<Field>::quad_corner_t(0);
  q->c_[0].h[1] = proofs::Quad<Field>::quad_corner_t(0);
  q->c_[0].v    = field_.one();

  // term1: -1 * wire1
  q->c_[1].g    = proofs::Quad<Field>::quad_corner_t(0);
  q->c_[1].h[0] = proofs::Quad<Field>::quad_corner_t(1);
  q->c_[1].h[1] = proofs::Quad<Field>::quad_corner_t(0);
  q->c_[1].v    = field_.one();
  field_.neg(q->c_[1].v);

  // Make quad canonical
  q->canonicalize(field_);

  layer.quad = std::move(q);
  l.clear();
  l.push_back(std::move(layer));

  // nl must match l.size()
  nl = l.size();

  std::cerr << "CTOR ninputs=" << ninputs
            << " npub_in=" << npub_in
            << " nv=" << nv
            << " logv=" << logv
            << " nl=" << nl
            << " nc=" << nc
            << " logc=" << logc
            << " subfield_boundary=" << subfield_boundary
            << " l.size=" << l.size()
            << " l[0].logw=" << l[0].logw
            << " quad_null=" << (l[0].quad == nullptr)
            << "\n";
}

}  // namespace zkp::internal
