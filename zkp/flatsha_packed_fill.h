#pragma once
#include <cstdint>
#include <stdexcept>


#include "circuits/logic/bit_plucker_constants.h"   // bit_plucker_point
#include "circuits/sha/flatsha256_witness.h"        // FlatSHA256Witness
#include "arrays/dense.h"                           // DenseFiller


namespace zkp {


// kShaPluckerSize=2 => each packed element encodes 2 bits => value in {0,1,2,3}
template <class FieldT>
static inline typename FieldT::Elt encode_2bits_as_plucker_point(const FieldT& f, uint32_t v2) {
  if (v2 > 3) throw std::runtime_error("2-bit value out of range");
  return proofs::bit_plucker_point<FieldT, 4>()(v2, f);
}


// Push one packed_v32 for a 32-bit word: 16 field elements (2 bits each).
template <class FieldT>
static inline void push_packed_v32_from_u32(
    proofs::DenseFiller<FieldT>& filler,
    const FieldT& f,
    uint32_t word
) {
  for (int i = 0; i < 16; i++) {
   uint32_t v2 = (word >> (2 * i)) & 0x3u;
    filler.push_back(encode_2bits_as_plucker_point<FieldT>(f, v2));
  }
}


// Push FlatSHA256Witness::BlockWitness in same order as circuit BlockWitness::input():
// outw[48], oute[64], outa[64], h1[8]
template <class FieldT>
static inline void push_flatsha_block_witness_packed(
    proofs::DenseFiller<FieldT>& filler,
    const FieldT& f,
    const proofs::FlatSHA256Witness::BlockWitness& bw
) {
  // outw[48]
  for (int k = 0; k < 48; k++) {
    push_packed_v32_from_u32<FieldT>(filler, f, bw.outw[k]);
  }


  // IMPORTANT: match BlockWitness::input() order: oute[k] THEN outa[k]
  for (int k = 0; k < 64; k++) {
    push_packed_v32_from_u32<FieldT>(filler, f, bw.oute[k]);
    push_packed_v32_from_u32<FieldT>(filler, f, bw.outa[k]);
  }


  // h1[8]
  for (int k = 0; k < 8; k++) {
    push_packed_v32_from_u32<FieldT>(filler, f, bw.h1[k]);
  }
}


} // namespace zkp


