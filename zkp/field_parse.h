#pragma once
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <algorithm>

#include "ec/p256.h"  // proofs::p256_base, proofs::p256_scalar, proofs::p256, proofs::n256_order

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

namespace zkp {

// -------------------- small helpers --------------------

static inline void require_32(const std::vector<uint8_t>& v, const char* name) {
  if (v.size() != 32) throw std::runtime_error(std::string(name) + " must be 32 bytes");
}

// Longfellow Nat::of_bytes() expects LITTLE-ENDIAN bytes (see nat.h).
static inline std::array<uint8_t,32> be32_to_le32(const std::vector<uint8_t>& be32) {
  require_32(be32, "be32");
  std::array<uint8_t,32> le{};
  std::copy(be32.begin(), be32.end(), le.begin());
  std::reverse(le.begin(), le.end());
  return le;
}

static inline BIGNUM* bn_from_32be(const std::vector<uint8_t>& be32) {
  require_32(be32, "be32");
  BIGNUM* bn = BN_bin2bn(be32.data(), (int)be32.size(), nullptr);
  if (!bn) throw std::runtime_error("BN_bin2bn failed");
  return bn;
}

static inline std::array<uint8_t,32> bn_to_32be(const BIGNUM* bn) {
  std::array<uint8_t,32> out{};
  if (BN_bn2binpad(bn, out.data(), (int)out.size()) != (int)out.size()) {
    throw std::runtime_error("BN_bn2binpad failed");
  }
  return out;
}

static inline BIGNUM* p256_group_order_bn() {
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (!group) throw std::runtime_error("EC_GROUP_new_by_curve_name failed");

  BIGNUM* order = BN_new();
  if (!order) {
    EC_GROUP_free(group);
    throw std::runtime_error("BN_new failed");
  }

  if (EC_GROUP_get_order(group, order, nullptr) != 1) {
    BN_free(order);
    EC_GROUP_free(group);
    throw std::runtime_error("EC_GROUP_get_order failed");
  }

  EC_GROUP_free(group);
  return order; // caller frees
}

// Reduce BE integer mod n (P-256 group order). Returns 32-byte BE.
inline std::array<uint8_t,32> reduce_32_be_mod_n(const std::vector<uint8_t>& be32) {
  require_32(be32, "be32");

  BIGNUM* x = bn_from_32be(be32);
  BIGNUM* order = p256_group_order_bn();

  BN_CTX* ctx = BN_CTX_new();
  if (!ctx) {
    BN_free(x); BN_free(order);
    throw std::runtime_error("BN_CTX_new failed");
  }

  BIGNUM* r = BN_new();
  if (!r) {
    BN_CTX_free(ctx);
    BN_free(x); BN_free(order);
    throw std::runtime_error("BN_new failed");
  }

  if (BN_mod(r, x, order, ctx) != 1) {
    BN_free(r);
    BN_CTX_free(ctx);
    BN_free(x); BN_free(order);
    throw std::runtime_error("BN_mod failed");
  }

  auto out = bn_to_32be(r);

  BN_free(r);
  BN_CTX_free(ctx);
  BN_free(x);
  BN_free(order);
  return out;
}

// -------------------- Base-field element parsing --------------------
// Inputs are OpenSSL-style big-endian. Convert to LE for Longfellow.
inline proofs::Fp256Base::Elt base_elt_from_32_be_strict(
    const std::vector<uint8_t>& be32,
    const char* name
) {
  require_32(be32, name);
  auto le = be32_to_le32(be32);
  auto v = proofs::p256_base.of_bytes_field(le.data());
  if (!v) {
    throw std::runtime_error(std::string(name) + " not canonical (<p) under Longfellow encoding");
  }
  return *v;
}

// -------------------- Base-field Nat parsing for VerifyWitness3 --------------------
//
// VerifyWitness3 takes Nat = EC::Field::N  (BASE FIELD Nat).
// But r/s must still be checked to lie in 1..n-1 (scalar range).
//
// These return proofs::Fp256Base::N (same underlying Nat<4>).

inline proofs::Fp256Base::N base_nat_from_32_be(const std::vector<uint8_t>& be32, const char* name) {
  require_32(be32, name);
  auto le = be32_to_le32(be32);
  return proofs::Fp256Base::N::of_bytes(le.data());
}

// r,s: range check in scalar field (OpenSSL), but return BASE-FIELD Nat for witness.
inline proofs::Fp256Base::N rs_as_base_nat_from_32_be_strict(
    const std::vector<uint8_t>& be32,
    const char* name
) {
  require_32(be32, name);

  BIGNUM* x = bn_from_32be(be32);
  BIGNUM* order = p256_group_order_bn();

  if (BN_is_zero(x) || BN_is_negative(x) || BN_cmp(x, order) >= 0) {
    BN_free(x);
    BN_free(order);
    throw std::runtime_error(std::string(name) + " not in scalar range 1..n-1");
  }

  BN_free(x);
  BN_free(order);

  return base_nat_from_32_be(be32, name);
}

// e for witness: e := digest mod n, returned as BASE-FIELD Nat holding that integer.
inline proofs::Fp256Base::N e_as_base_nat_from_digest_mod_n(const std::vector<uint8_t>& digest32_be) {
  require_32(digest32_be, "e");
  auto red_be = reduce_32_be_mod_n(digest32_be);
  std::vector<uint8_t> red_be_vec(red_be.begin(), red_be.end());
  return base_nat_from_32_be(red_be_vec, "e_red");
}

} // namespace zkp