#include "ecdsa_circuit.h"

#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "ec/p256.h"

namespace zkp {

std::unique_ptr<proofs::Circuit<Field>> build_ecdsa_verify_circuit() {
  using CompilerBackend = proofs::CompilerBackend<Field>;
  using LogicCircuit    = proofs::Logic<Field, CompilerBackend>;
  using EltW            = typename LogicCircuit::EltW;
  using Verc            = proofs::VerifyCircuit<LogicCircuit, Field, proofs::P256>;

  proofs::QuadCircuit<Field> Q(proofs::p256_base);
  const CompilerBackend cbk(&Q);
  const LogicCircuit lc(&cbk, proofs::p256_base);

  Verc verc(lc, proofs::p256, proofs::n256_order);

  // EXACTLY like zk_test.cc: only pkx, pky, e are inputs here.
  EltW pkx = lc.eltw_input();
  EltW pky = lc.eltw_input();
  EltW e   = lc.eltw_input();

  // Everything after this is private witness.
  Q.private_input();

  Verc::Witness vwc;
  vwc.input(lc);

 // verc.verify_signature3(pkx, pky, e, vwc);

  // EXACTLY like zk_test.cc
  return Q.mkcircuit(1);
}

} // namespace zkp