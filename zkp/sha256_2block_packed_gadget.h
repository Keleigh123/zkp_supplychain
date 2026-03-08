#pragma once
#include <array>
#include <cstdint>


#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_io.h"
#include "circuits/logic/bit_plucker.h"


namespace zkp {


static inline constexpr uint32_t kShaIV[8] = {
  0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};


static inline constexpr uint32_t kPadBlock64B[16] = {
  0x80000000u, 0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x00000200u
};


template <class Logic, class PackedV32>
static inline PackedV32 mux_packed_v32(
    const Logic& lc,
    const typename Logic::EltW& sel_bit,
    const PackedV32& a,
    const PackedV32& b
) {
    PackedV32 out{};
    lc.assert_is_bit(sel_bit);


    for (size_t i = 0; i < out.size(); i++) {
        auto diff = lc.sub(&b[i], a[i]);      // b - a
        auto prod = lc.mul(&sel_bit, diff);   // sel*(b-a)
        out[i] = lc.add(&a[i], prod);         // a + ...
    }
    return out;
}


// SHA256 over exactly 64 bytes, input as 16 packed 32-bit words.
// Returns digest as 8 packed words, and consumes two BlockWitnesses.
// SHA256 over exactly 64 bytes, input as 16 packed 32-bit words.
// Returns digest as 8 packed words, and consumes two BlockWitnesses.
template <class Logic>
static inline std::array<typename proofs::FlatSHA256Circuit<
    Logic, proofs::BitPlucker<Logic, proofs::kShaPluckerSize>>::packed_v32, 8>
sha256_64bytes_2block_packed(
    const proofs::FlatSHA256Circuit<
        Logic, proofs::BitPlucker<Logic, proofs::kShaPluckerSize>>& sha,
    const Logic& lc,
    const typename proofs::FlatSHA256Circuit<
        Logic, proofs::BitPlucker<Logic, proofs::kShaPluckerSize>>::packed_v32 in0_packed[16],
    typename proofs::FlatSHA256Circuit<
        Logic, proofs::BitPlucker<Logic, proofs::kShaPluckerSize>>::BlockWitness& bw0,
    typename proofs::FlatSHA256Circuit<
        Logic, proofs::BitPlucker<Logic, proofs::kShaPluckerSize>>::BlockWitness& bw1
) {
  using BitPlk  = proofs::BitPlucker<Logic, proofs::kShaPluckerSize>;
  using FlatSha = proofs::FlatSHA256Circuit<Logic, BitPlk>;
  using packed_v32 = typename FlatSha::packed_v32;
  using v32 = typename Logic::v32;


  // Build H0 as v32 constants
  v32 H0[8];
  for (int i = 0; i < 8; i++) H0[i] = lc.vbit32(kShaIV[i]);


  // Unpack in0 into v32 words
  v32 in0[16];
  for (int i = 0; i < 16; i++) in0[i] = sha.bp_.unpack_v32(in0_packed[i]);


  // ---- Unpack bw0 (packed_v32 -> v32) ----
  v32 outw0[48];
  v32 oute0[64];
  v32 outa0[64];
  v32 h1_0[8];


  for (int k = 0; k < 48; k++) outw0[k] = sha.bp_.unpack_v32(bw0.outw[k]);
  for (int k = 0; k < 64; k++) {
    oute0[k] = sha.bp_.unpack_v32(bw0.oute[k]);
    outa0[k] = sha.bp_.unpack_v32(bw0.outa[k]);
  }
  for (int k = 0; k < 8; k++) h1_0[k] = sha.bp_.unpack_v32(bw0.h1[k]);


  // Block0: constrain witness
  sha.assert_transform_block(in0, H0, outw0, oute0, outa0, h1_0);


  // H1 is the block0 output bits
  v32 H1[8];
  for (int i = 0; i < 8; i++) H1[i] = h1_0[i];


  // Block1 is fixed padding for 64-byte message
  v32 in1[16];
  for (int i = 0; i < 16; i++) in1[i] = lc.vbit32(kPadBlock64B[i]);


  // ---- Unpack bw1 (packed_v32 -> v32) ----
  v32 outw1[48];
  v32 oute1[64];
  v32 outa1[64];
  v32 h1_1[8];


  for (int k = 0; k < 48; k++) outw1[k] = sha.bp_.unpack_v32(bw1.outw[k]);
  for (int k = 0; k < 64; k++) {
    oute1[k] = sha.bp_.unpack_v32(bw1.oute[k]);
    outa1[k] = sha.bp_.unpack_v32(bw1.outa[k]);
  }
  for (int k = 0; k < 8; k++) h1_1[k] = sha.bp_.unpack_v32(bw1.h1[k]);


  // Block1: constrain witness (final digest bits)
  sha.assert_transform_block(in1, H1, outw1, oute1, outa1, h1_1);


  // Return packed digest words (the packed wires are bw1.h1)
  std::array<packed_v32, 8> out{};
  for (int i = 0; i < 8; i++) out[i] = bw1.h1[i];
  return out;
}


} // namespace zkp



