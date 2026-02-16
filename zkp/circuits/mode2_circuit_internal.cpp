#include "mode2_circuit_internal.h"


#include "sumcheck/circuit.h"
#include "sumcheck/quad.h"


namespace zkp::internal {


using Field = proofs::Fp256<>;


Mode2Circuit::Mode2Circuit() {
    Field F;   // <-- REQUIRED


    ninputs = 2;
    npub_in = 1;
    nl = 1;        // ADD THIS
    nc = 1;        // ADD THIS


    proofs::Layer<Field> layer;
    layer.nw = 2;
    layer.logw = 1;


    auto q = std::make_unique<proofs::Quad<Field>>(2);


    // +1 * wire0
    q->c_[0].g    = proofs::Quad<Field>::quad_corner_t(0);
    q->c_[0].h[0] = proofs::Quad<Field>::quad_corner_t(0);
    q->c_[0].h[1] = proofs::Quad<Field>::quad_corner_t(0);
    q->c_[0].v    = F.one();   // ✅ instance method


    // -1 * wire1
    q->c_[1].g    = proofs::Quad<Field>::quad_corner_t(0);
    q->c_[1].h[0] = proofs::Quad<Field>::quad_corner_t(1);
    q->c_[1].h[1] = proofs::Quad<Field>::quad_corner_t(0);
    q->c_[1].v    = F.one();
    F.neg(q->c_[1].v);         // ✅ negates in-place


    q->canonicalize(F);


    layer.quad = std::move(q);
    l.push_back(std::move(layer));

     nl = l.size();

}


} // namespace zkp::internal
