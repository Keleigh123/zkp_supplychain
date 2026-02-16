#pragma once

#include <cstdint>
#include <vector>
#include "circuits/mode2_circuit_internal.h" 

namespace zkp {

 struct Mode2Prover;
 struct Mode2Verifier;
// ---------- Circuit definition ----------
// mode2_circuit.h
struct Mode2Circuit {
    zkp::internal::Mode2Circuit circuit;

    Mode2Circuit() = default;
    ~Mode2Circuit() = default;

    Mode2Circuit(const Mode2Circuit&) = delete;
    Mode2Circuit& operator=(const Mode2Circuit&) = delete;
    // Mode2Circuit(Mode2Circuit&&) = delete;
    // Mode2Circuit& operator=(Mode2Circuit&&) = delete;

    // const proofs::Fp<256>& field() const {
    //     return circuit.field();
    // }
};



// ---------- Circuit lifecycle ----------
Mode2Circuit* create_mode2_circuit();
void destroy_mode2_circuit(Mode2Circuit* c);

// ---------- Prover ----------
Mode2Prover* create_mode2_prover(Mode2Circuit* c);
void destroy_mode2_prover(Mode2Prover* p);

bool mode2_prove(
    Mode2Prover* prover,
    const uint8_t* public_inputs,
    size_t public_len,
    const uint8_t* private_inputs,
    size_t private_len,
    std::vector<uint8_t>& proof_out
);

// ---------- Verifier ----------
Mode2Verifier* create_mode2_verifier(Mode2Circuit* c);
void destroy_mode2_verifier(Mode2Verifier* v);

bool mode2_verify(
    Mode2Verifier* verifier,
    const uint8_t* public_inputs,
    size_t public_len,
    const uint8_t* proof,
    size_t proof_len
);

bool run_prover(
    const std::vector<uint8_t>& pub_input,
    const std::vector<uint8_t>& priv_input, 
    std::vector<uint8_t>& proof_out
);

} // namespace zkp
