#include "ecdsa_merkle_prover.h"
#include "ecdsa_merkle_circuit.h"


#include "arrays/dense.h"
#include "circuits/ecdsa/verify_witness.h"
#include "random/transcript.h"
#include "random/secure_random_engine.h"
#include "algebra/fp2.h"
#include "algebra/convolution.h"
#include "algebra/reed_solomon.h"
#include "ec/p256.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"


#include "field_parse.h"
#include "../utils/crypto_utils.h"          // sha256 if needed elsewhere
#include "flatsha_packed_fill.h"        // pack helpers


#include "circuits/sha/flatsha256_witness.h"

#include <iostream>
#include <vector>
#include <stdexcept>
#include <cstring>


namespace zkp {


using Field = proofs::Fp256Base;
using Elt   = Field::Elt;
using Nat   = proofs::Fp256Base::N;


using Field2 = proofs::Fp2<Field>;
using FftExtConvolutionFactory = proofs::FFTExtConvolutionFactory<Field, Field2>;
using RSFactory = proofs::ReedSolomonFactory<Field, FftExtConvolutionFactory>;


constexpr size_t kLigeroRate = 2;
constexpr size_t kLigeroNreq = 1;
static constexpr size_t kVersion = 4;


static inline void bytes64_to_u32be16(const uint8_t b[64], uint32_t out[16]) {
  for (int i = 0; i < 16; i++) {
    out[i] = (uint32_t(b[4*i+0]) << 24) |
             (uint32_t(b[4*i+1]) << 16) |
             (uint32_t(b[4*i+2]) <<  8) |
             (uint32_t(b[4*i+3]) <<  0);
  }
}


static inline void sha256_iv(uint32_t H0[8]) {
  H0[0]=0x6a09e667u; H0[1]=0xbb67ae85u; H0[2]=0x3c6ef372u; H0[3]=0xa54ff53au;
  H0[4]=0x510e527fu; H0[5]=0x9b05688cu; H0[6]=0x1f83d9abu; H0[7]=0x5be0cd19u;
}


// Build 2-block FlatSHA witnesses for hashing exactly 64 bytes.
static inline void build_sha2block_witness_64(
    const uint8_t msg64[64],
    proofs::FlatSHA256Witness::BlockWitness& bw0,
    proofs::FlatSHA256Witness::BlockWitness& bw1
) {
  uint32_t H0[8]; sha256_iv(H0);


  uint32_t in0[16];
  bytes64_to_u32be16(msg64, in0);


  uint32_t H1[8];
  proofs::FlatSHA256Witness::transform_and_witness_block(
      in0, H0, bw0.outw, bw0.oute, bw0.outa, H1
  );


  uint32_t in1[16] = {
    0x80000000u, 0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x00000200u
  };


  uint32_t H2[8];
  proofs::FlatSHA256Witness::transform_and_witness_block(
      in1, H1, bw1.outw, bw1.oute, bw1.outa, H2
  );
}


Proof generate_ecdsa_merkle_proof(const EcdsaMerkleProofInput& in, PublicInputs& pub) {
  //in - inputs used to build witness
  //pub - inputs that are public
  std::cerr
  << "sizes: root=" << in.approved_root_32.size()
  << " pkx=" << in.pkx_32.size()
  << " pky=" << in.pky_32.size()
  << " e=" << in.e_32.size()
  << " r=" << in.r_32.size()
  << " s=" << in.s_32.size()
  << " siblings=" << in.siblings_32.size()
  << " dirs=" << in.dirs.size()
  << "\n";
  if (in.approved_root_32.size() != 32) throw std::runtime_error("approved_root must be 32 bytes");
  if (in.pkx_32.size() != 32 || in.pky_32.size() != 32) throw std::runtime_error("pkx/pky must be 32 bytes");
  if (in.e_32.size() != 32 || in.r_32.size() != 32 || in.s_32.size() != 32) throw std::runtime_error("e/r/s must be 32 bytes");


  constexpr int D = 3;
  if ((int)in.siblings_32.size() != D) throw std::runtime_error("siblings must have depth 3");
  if ((int)in.dirs.size() != D) throw std::runtime_error("dirs must have depth 3");
  for (int i = 0; i < D; i++) if (in.siblings_32[i].size() != 32) throw std::runtime_error("each sibling must be 32 bytes");


  auto circuit = build_ecdsa_merkle_verify_circuit();
if (circuit->npub_in != 130) {
  throw std::runtime_error("BUG: circuit->npub_in != 130, got " + std::to_string(circuit->npub_in));
}

  // ---- Public inputs: (1) + approved_root packed as 8 u32 BE words (each word packed into 16 elts)
  // Convert approved_root bytes to 8 big-endian u32 words:
  uint32_t root_words[8];
  for (int i = 0; i < 8; i++) {
    root_words[i] = (uint32_t(in.approved_root_32[4*i+0]) << 24) |
                    (uint32_t(in.approved_root_32[4*i+1]) << 16) |
                    (uint32_t(in.approved_root_32[4*i+2]) <<  8) |
                    (uint32_t(in.approved_root_32[4*i+3]) <<  0);
  }


  // ---- ECDSA parse (matches your Step-1 prover)
  Elt pkx_elt = zkp::base_elt_from_32_be_strict(in.pkx_32, "pkx");
  Elt pky_elt = zkp::base_elt_from_32_be_strict(in.pky_32, "pky");


  Nat r = zkp::rs_as_base_nat_from_32_be_strict(in.r_32, "r");
  Nat s = zkp::rs_as_base_nat_from_32_be_strict(in.s_32, "s");
 Nat e_nat = zkp::e_as_base_nat_from_digest_mod_n(in.e_32);

// Build the *wire* element from bytes (same style as pkx/pky)
auto e_red_be = zkp::reduce_32_be_mod_n(in.e_32);
std::vector<uint8_t> e_red_be_vec(e_red_be.begin(), e_red_be.end());
Elt e_wire = zkp::base_elt_from_32_be_strict(e_red_be_vec, "e_red");


  using Verw = proofs::VerifyWitness3<proofs::P256, proofs::Fp256Scalar>;
  Verw vw(proofs::p256_scalar, proofs::p256);


  if (!vw.compute_witness(pkx_elt, pky_elt, e_nat, r, s)) {
    throw std::runtime_error("ECDSA witness computation failed");
  }
std::cerr << "circuit->ninputs=" << circuit->ninputs
          << " npub_in=" << circuit->npub_in
          << "\n";

  // ---- Build witness W
proofs::Dense<Field> W(1, circuit->ninputs);
proofs::DenseFiller<Field> filler(W);
auto dump_idx = [&](size_t idx) {
  uint8_t b[32];
  proofs::p256_base.to_bytes_field(b, W.at(idx));
  std::cerr << "[W@" << idx << "] 0x";
  static const char* hex = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    std::cerr << hex[b[i] >> 4] << hex[b[i] & 0xF];
  }
  std::cerr << "\n";
};
auto mark = [&](const char* tag) {
  std::cerr << "[MARK] " << tag
            << " filler.size=" << filler.size()
            << " (ninputs=" << circuit->ninputs
            << " npub_in=" << circuit->npub_in
            << ")\n";
};
  // 0) public ONE
filler.push_back(proofs::p256_base.zero());
filler.push_back(proofs::p256_base.one());  // pub[1]

  // 1) public approved_root packed (8 words * 16 elts per word)
  for (int w = 0; w < 8; w++) {
    zkp::push_packed_v32_from_u32(filler, proofs::p256_base, root_words[w]);
  }

  // 2) EXTRA public input to match npub_in=130  (TEMP VALUE)
 // filler.push_back(proofs::p256_base.zero());
  if (filler.size() != circuit->npub_in) {
    throw std::runtime_error("BUG: after public inputs filler.size=" +
                             std::to_string(filler.size()) +
                             " but npub_in=" + std::to_string(circuit->npub_in));
  }

mark("after pub(one+root)");

  // ---- Private inputs start (matches circuit order)
  filler.push_back(pkx_elt);
  filler.push_back(pky_elt);
  filler.push_back(e_wire);

  mark("after pkx/pky/e");

  // pkx||pky bytes as 64 bytes -> 16 u32 words BE
  uint8_t pkmsg64[64];
  memcpy(pkmsg64 + 0,  in.pkx_32.data(), 32);
  memcpy(pkmsg64 + 32, in.pky_32.data(), 32);


  uint32_t pk_words16[16];
  bytes64_to_u32be16(pkmsg64, pk_words16);
  for (int i = 0; i < 16; i++) {
    zkp::push_packed_v32_from_u32(filler, proofs::p256_base, pk_words16[i]);
  }
mark("after pk_words16");

  // dirs + siblings packed
  for (int i = 0; i < D; i++) {
    if (in.dirs[i] > 1) throw std::runtime_error("dir must be 0/1");
    filler.push_back(proofs::p256_base.of_scalar(in.dirs[i])); // dir bit as field elt 0/1


    // sibling digest words
    uint32_t sib_words[8];
    for (int w = 0; w < 8; w++) {
      sib_words[w] = (uint32_t(in.siblings_32[i][4*w+0]) << 24) |
                     (uint32_t(in.siblings_32[i][4*w+1]) << 16) |
                     (uint32_t(in.siblings_32[i][4*w+2]) <<  8) |
                     (uint32_t(in.siblings_32[i][4*w+3]) <<  0);
    }
    for (int w = 0; w < 8; w++) zkp::push_packed_v32_from_u32(filler, proofs::p256_base, sib_words[w]);
  }

mark("after dirs+sibs");
  // ---- SHA witnesses (exactly as circuit allocates them)
  // Hashes in circuit:
  //  1) leaf = SHA(pkx||pky)                     => 2 blocks
  //  2) level0 = SHA(mux(node,sib0) || mux(..))  => 2 blocks
  //  3) level1 => 2 blocks
  //  4) level2 => 2 blocks
  // Total = 4 hashes * 2 blocks = 8 BlockWitness objects


  // We must build the exact 64-byte blocks the prover is implicitly selecting.
  // IMPORTANT: The circuit uses dirs to choose order, so prover must follow same order.


  // Helper to compute next msg64 = (node||sib) or (sib||node), where node/sib are 32-byte digests.
  auto make_level_msg64 = [&](const std::array<uint8_t,32>& node,
                              const std::vector<uint8_t>& sib,
                              uint8_t dir,
                              uint8_t out64[64]) {
    if (dir == 0) {
      memcpy(out64 + 0,  node.data(), 32);
      memcpy(out64 + 32, sib.data(),  32);
    } else {
      memcpy(out64 + 0,  sib.data(),  32);
      memcpy(out64 + 32, node.data(), 32);
    }
  };


  // We’ll use libsodium SHA (already in your project) to compute digest bytes for next level blocks
  // to build FlatSHA witnesses correctly.
  auto sha256_bytes = [&](const uint8_t* data, size_t len) -> std::array<uint8_t,32> {
    std::vector<uint8_t> v(data, data + len);
    auto d = sha256(v);
    std::array<uint8_t,32> out{};
    memcpy(out.data(), d.data(), 32);
    return out;
  };


  // leaf digest bytes
  auto node = sha256_bytes(pkmsg64, 64);


  // 1) leaf hash witnesses
  {
    proofs::FlatSHA256Witness::BlockWitness bw0{}, bw1{};
    build_sha2block_witness_64(pkmsg64, bw0, bw1);
    zkp::push_flatsha_block_witness_packed(filler, proofs::p256_base, bw0);
    zkp::push_flatsha_block_witness_packed(filler, proofs::p256_base, bw1);
  }
mark("after sha leaf");

  // 2..4) Merkle levels
  for (int i = 0; i < D; i++) {
    uint8_t msg64[64];
    make_level_msg64(node, in.siblings_32[i], in.dirs[i], msg64);


    // witnesses for this level hash
    proofs::FlatSHA256Witness::BlockWitness bw0{}, bw1{};
    build_sha2block_witness_64(msg64, bw0, bw1);
    zkp::push_flatsha_block_witness_packed(filler, proofs::p256_base, bw0);
    zkp::push_flatsha_block_witness_packed(filler, proofs::p256_base, bw1);

mark((std::string("after sha level ") + std::to_string(i)).c_str());
    // update node digest for next level
    node = sha256_bytes(msg64, 64);
  }
 
 
mark("before vw.fill_witness");
size_t vw_start = filler.size();   // should be 24327
vw.fill_witness(filler);
std::cerr << "ninputs=" << circuit->ninputs
          << " filler.size=" << filler.size() << "\n";

dump_idx(0);
dump_idx(128);
dump_idx(circuit->ninputs - 1);

dump_idx(25256);
dump_idx(25257);
dump_idx(25258);
size_t vw_end = filler.size();     // should be 25361
mark("after vw.fill_witness");

std::cerr << "[VW RANGE] start=" << vw_start
          << " end=" << vw_end
          << " count=" << (vw_end - vw_start) << "\n";
std::cerr << "[VW FAIL OFFSET GUESS] xoff=" << (25256 - vw_start)
          << " yoff=" << (25257 - vw_start)
          << " zoff=" << (25258 - vw_start) << "\n";

  // ---- Public input Dense: size = npub_in = 129
proofs::Dense<Field> Pub(1, circuit->npub_in);
proofs::DenseFiller<Field> pubfill(Pub);


pubfill.push_back(proofs::p256_base.zero());
  pubfill.push_back(proofs::p256_base.one());
  for (int w = 0; w < 8; w++) zkp::push_packed_v32_from_u32(pubfill, proofs::p256_base, root_words[w]);
   // EXTRA public input (must match what you put in W)
  
std::cerr << "[DENSE] Pub: n0=" << Pub.n0_ << " n1=" << Pub.n1_
          << " (expect n0=1, n1=" << circuit->npub_in << ")\n";

  // Ligero setup (same as your Step-1 ECDSA prover)
  Field2 base2(proofs::p256_base);
  Field2::Elt omega{
      proofs::p256_base.of_string("0xf90d338ebd84f5665cfc85c67990e3379fc9563b382a4a4c985a65324b242562"),
      proofs::p256_base.of_string("0xb9e81e42bc97cc4da04fc2e20106e34084738a6474d232c6dbf4174f60a43eac")
  };
  uint64_t root_order = 1ull << 31;


  FftExtConvolutionFactory fft(proofs::p256_base, base2, omega, root_order);
  RSFactory rsf(fft, proofs::p256_base);


  proofs::ZkProof<Field> zkpr(*circuit, kLigeroRate, kLigeroNreq);
  proofs::Transcript tp(reinterpret_cast<const uint8_t*>("ecdsa_merkle"), 11, kVersion);
  proofs::SecureRandomEngine rng;


  proofs::ZkProver<Field, RSFactory> prover(*circuit, proofs::p256_base, rsf);

std::cerr << "ninputs=" << circuit->ninputs
          << " npub_in=" << circuit->npub_in << "\n";
std::cerr << "filled=" << filler.size() << "\n"; 
std::cerr << "[BEFORE COMMIT]\n";
dump_idx(25256);
dump_idx(25257);
dump_idx(25258);
std::cerr << "[DENSE] W: n0=" << W.n0_ << " n1=" << W.n1_
          << " (expect n0=1, n1=" << circuit->ninputs << ")\n";

          if (filler.size() != circuit->ninputs) {
  throw std::runtime_error("BUG: filled witness size " + std::to_string(filler.size()) +
                           " != circuit->ninputs " + std::to_string(circuit->ninputs));
}
  prover.commit(zkpr, W, tp, rng);
  if (!prover.prove(zkpr, W, tp)) throw std::runtime_error("prove failed");


  std::vector<uint8_t> proof_bytes;
  zkpr.write(proof_bytes, proofs::p256_base);


  // Serialize public inputs (store as bytes per field element; easiest is store raw field encoding stream)
  // For now: store each pub element as 32 bytes (Longfellow base field encoding).
 pub.data.clear();
pub.data.resize(32 * circuit->npub_in);


size_t off = 0;
auto write_elt = [&](const Elt& x) {
  proofs::p256_base.to_bytes_field(pub.data.data() + off, x);
  off += 32;
};


// Public inputs are EXACTLY what you pushed into Pub:
// 0) ONE
//write_elt(proofs::p256_base.one());


// 1) approved_root packed: 8 words, each word => 16 packed elts (2-bit plucker points)
// for (int w = 0; w < 8; w++) {
//   for (int i = 0; i < 16; i++) {
//    uint32_t v2 = (root_words[w] >> (2 * i)) & 0x3u;
//     Elt pt = proofs::bit_plucker_point<Field, 4>()(v2, proofs::p256_base);
//     write_elt(pt);
//   }
// }
// pub[0], pub[1]
write_elt(proofs::p256_base.zero());
write_elt(proofs::p256_base.one());

// then the 128 packed root points
for (int w = 0; w < 8; w++) {
  for (int i = 0; i < 16; i++) {
    uint32_t v2 = (root_words[w] >> (2 * i)) & 0x3u;
    Elt pt = proofs::bit_plucker_point<Field, 4>()(v2, proofs::p256_base);
    write_elt(pt);
  }
}

if (off != pub.data.size()) {
  throw std::runtime_error("pub serialization size mismatch");
}


  return { std::move(proof_bytes) };
}


} // namespace zkp



