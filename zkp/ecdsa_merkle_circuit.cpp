#include "ecdsa_merkle_circuit.h"


#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "ec/p256.h"
#include <iostream>

#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_io.h"
#include "circuits/logic/bit_plucker.h"


#include "sha256_2block_packed_gadget.h"


namespace zkp {


std::unique_ptr<proofs::Circuit<Field>> build_ecdsa_merkle_verify_circuit() {
  using CompilerBackend = proofs::CompilerBackend<Field>;
  using LogicCircuit    = proofs::Logic<Field, CompilerBackend>;
  using EltW            = typename LogicCircuit::EltW;
  using Verc            = proofs::VerifyCircuit<LogicCircuit, Field, proofs::P256>;


  using BitPlk  = proofs::BitPlucker<LogicCircuit, proofs::kShaPluckerSize>;
  using FlatSha = proofs::FlatSHA256Circuit<LogicCircuit, BitPlk>;
  using packed_v32 = typename FlatSha::packed_v32;


  proofs::QuadCircuit<Field> Q(proofs::p256_base);
 auto markQ = [&](const char* tag) {
  std::cerr << "[CIRCUIT] " << tag
            << " ninput_=" << Q.ninput_
            << "\n";
};
  const CompilerBackend cbk(&Q);
  const LogicCircuit lc(&cbk, proofs::p256_base);


  Verc verc(lc, proofs::p256, proofs::n256_order);
  FlatSha sha(lc);


  // -------------------------
  // PUBLIC INPUTS: 1 + approved_root (256-bit as 8 packed 32-bit words)
  // -------------------------
  EltW one = lc.eltw_input(); //longfellow requires an input constant 1


  EltW oneC = lc.konst(lc.f_.one());
auto one_diff = lc.sub(&one, oneC);
lc.assert0(one_diff);
std::cerr << "[CIRCUIT] pub start ninput_=" << Q.ninput_ << "\n";
  packed_v32 approved_root_packed[8];
  for (int i = 0; i < 8; i++) {
    approved_root_packed[i] = FlatSha::packed_input(lc); // 16 EltW each
    std::cerr << "[CIRCUIT] after root[" << i << "] ninput_=" << Q.ninput_ << "\n";
  }
markQ("after pub(one+root)");
std::cerr << "[CIRCUIT] before private_input ninput_=" << Q.ninput_ << "\n";
  // Everything after is private
  Q.private_input();
markQ("after Q.private_input");

  // -------------------------
  // PRIVATE INPUTS: ECDSA side (field elts)
  // -------------------------
  EltW pkx_elt = lc.eltw_input();
  EltW pky_elt = lc.eltw_input();
  EltW e_elt   = lc.eltw_input(); // private e

markQ("after pkx/pky/e");
  // -------------------------
  // PRIVATE INPUTS: Merkle leaf bytes as 16 packed words (pkx||pky big-endian)
  // -------------------------
  packed_v32 pk_bytes_words[16];
  for (int i = 0; i < 16; i++) pk_bytes_words[i] = FlatSha::packed_input(lc);

markQ("after pk_words16");
  // Merkle path: depth 3
  constexpr int D = 3;
  EltW dir[D];
  packed_v32 sibling_words[D][8]; // each sibling digest is 8 packed words


  for (int i = 0; i < D; i++) {
    dir[i] = lc.eltw_input();
    lc.assert_is_bit(dir[i]);
    for (int w = 0; w < 8; w++) sibling_words[i][w] = FlatSha::packed_input(lc);
  }
markQ("after dirs+sibs");

  // -------------------------
  // MERKLE: leaf = SHA256(pkx||pky)
  // -------------------------
  // For each 2-block SHA we need two BlockWitness inputs
  FlatSha::BlockWitness leaf_bw0; leaf_bw0.input(lc);
  FlatSha::BlockWitness leaf_bw1; leaf_bw1.input(lc);
markQ("after sha leaf");

  auto node = zkp::sha256_64bytes_2block_packed(sha, lc, pk_bytes_words, leaf_bw0, leaf_bw1); // node: 8 packed words


  // Fold 3 levels
  for (int i = 0; i < D; i++) {
    // Build next input block words = (node||sib) or (sib||node) depending on dir
    packed_v32 inwords[16];
    for (int w = 0; w < 8; w++) {
      inwords[w]     = zkp::mux_packed_v32(lc, dir[i], node[w], sibling_words[i][w]); // sel? b:a with our mux
      inwords[w + 8] = zkp::mux_packed_v32(lc, dir[i], sibling_words[i][w], node[w]);
    }


    FlatSha::BlockWitness bw0; bw0.input(lc);
    FlatSha::BlockWitness bw1; bw1.input(lc);
    if (i == 0) markQ("after sha level 0");
  if (i == 1) markQ("after sha level 1");
  if (i == 2) markQ("after sha level 2");
    node = zkp::sha256_64bytes_2block_packed(sha, lc, inwords, bw0, bw1);
  }


  // Assert node == approved_root
  for (int w = 0; w < 8; w++) {
    for (size_t k = 0; k < approved_root_packed[w].size(); k++) {
         auto diff = lc.sub(&node[w][k], approved_root_packed[w][k]);
lc.assert0(diff);
    }
  }


  // -------------------------
  // ECDSA VERIFY (private pkx,pky,e)
  // -------------------------
  Verc::Witness vwc;
  vwc.input(lc);
  markQ("after ecdsa_witness");
  verc.verify_signature3(pkx_elt, pky_elt, e_elt, vwc);


auto c = Q.mkcircuit(/*nc=*/1);
std::cerr << "mkcircuit: ninputs=" << c->ninputs
          << " npub_in=" << c->npub_in
          << " nc=" << c->nc
          << "\n";
return c;
}


} // namespace zkp
