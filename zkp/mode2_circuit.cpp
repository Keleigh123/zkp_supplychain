#include "mode2_circuit.h"
#include "circuits/mode2_circuit_internal.h"

#include "algebra/fp_p256.h"
#include <vector>
#include "prover.h"
#include "verifier.h"

using namespace proofs;

namespace zkp {

using Field = proofs::Fp256<>;
using Elt   = Field::Elt;

static bool bytes_to_elts(
    const Field& field,
    const uint8_t* in,
    size_t len,
    std::vector<Elt>& out
) {
    if (len % Field::kBytes != 0) return false;
    size_t n = len / Field::kBytes;
    out.resize(n);

    for (size_t i = 0; i < n; i++) {
        auto v = field.of_bytes_field(in + i * Field::kBytes);
        if (!v) return false;
        out[i] = *v;
    }
    return true;
}

Mode2Circuit* create_mode2_circuit() { return new Mode2Circuit{}; }
void destroy_mode2_circuit(Mode2Circuit* c) { delete c; }

Mode2Prover* create_mode2_prover(Mode2Circuit* c) { return new Mode2Prover{*c}; }
void destroy_mode2_prover(Mode2Prover* p) { delete p; }

Mode2Verifier* create_mode2_verifier(Mode2Circuit* c) { return new Mode2Verifier{*c}; }
void destroy_mode2_verifier(Mode2Verifier* v) { delete v; }

bool mode2_prove(
    Mode2Prover* prover,
    const uint8_t* public_inputs,
    size_t public_len,
    const uint8_t* private_inputs,
    size_t private_len,
    std::vector<uint8_t>& proof_out
) {
    if (public_len != Field::kBytes || private_len != Field::kBytes) return false;

    const Field& field = prover->c.circuit.field();

    std::vector<Elt> pub, priv;
    if (!bytes_to_elts(field, public_inputs, public_len, pub)) return false;
    if (!bytes_to_elts(field, private_inputs, private_len, priv)) return false;
    if (pub.size() != 1 || priv.size() != 1) return false;

    std::vector<uint8_t> buf(65536);
    bool ok = prover->prove(pub[0], priv[0], buf.data(), buf.size());
    if (!ok) return false;

    // shrink to actual proof length (set by Mode2Prover::prove)
    proof_out.assign(buf.begin(), buf.begin() + prover->last_proof_len_);
    return true;
}

bool mode2_verify(
    Mode2Verifier* verifier,
    const uint8_t* public_inputs,
    size_t public_len,
    const uint8_t* proof_in,
    size_t proof_len
) {
    const Field& field = verifier->c.circuit.field();

    std::vector<Elt> pub;
    if (!bytes_to_elts(field, public_inputs, public_len, pub)) return false;
    if (pub.size() != 1) return false;

    return verifier->verify(pub[0], proof_in, proof_len);
}

bool run_prover(
    const std::vector<uint8_t>& pub_input,
    const std::vector<uint8_t>& priv_input,
    std::vector<uint8_t>& proof_out
) {
    Mode2Circuit* c = create_mode2_circuit();
    Mode2Prover*  p = create_mode2_prover(c);

    bool ok = mode2_prove(
        p,
        pub_input.data(), pub_input.size(),
        priv_input.data(), priv_input.size(),
        proof_out
    );

    destroy_mode2_prover(p);
    destroy_mode2_circuit(c);
    return ok;
}

} // namespace zkp
