#pragma once
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

static inline void require_32(const std::vector<uint8_t>& v, const char* name) {
  if (v.size() != 32) throw std::runtime_error(std::string(name) + " must be 32 bytes");
}

static inline std::vector<uint8_t> rev32(const std::vector<uint8_t>& v) {
  require_32(v, "rev32");
  std::vector<uint8_t> r = v;
  std::reverse(r.begin(), r.end());
  return r;
}

static inline BIGNUM* bn_from_32be(const std::vector<uint8_t>& be32) {
  require_32(be32, "bn_from_32be");
  BIGNUM* bn = BN_bin2bn(be32.data(), (int)be32.size(), nullptr);
  if (!bn) throw std::runtime_error("BN_bin2bn failed");
  return bn;
}

// Verify ECDSA(P-256) with OpenSSL. digest32 must be a 32-byte digest.
static inline bool openssl_verify_p256_sig(
    const std::vector<uint8_t>& pkx32_be,
    const std::vector<uint8_t>& pky32_be,
    const std::vector<uint8_t>& digest32,
    const std::vector<uint8_t>& r32_be,
    const std::vector<uint8_t>& s32_be
) {
  require_32(pkx32_be, "pkx");
  require_32(pky32_be, "pky");
  require_32(digest32, "digest");
  require_32(r32_be, "r");
  require_32(s32_be, "s");

  bool ok = false;

  EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!key) throw std::runtime_error("EC_KEY_new_by_curve_name failed");

  const EC_GROUP* group = EC_KEY_get0_group(key);
  EC_POINT* point = EC_POINT_new(group);
  if (!point) {
    EC_KEY_free(key);
    throw std::runtime_error("EC_POINT_new failed");
  }

  BIGNUM* x = bn_from_32be(pkx32_be);
  BIGNUM* y = bn_from_32be(pky32_be);

  if (EC_POINT_set_affine_coordinates(group, point, x, y, nullptr) != 1) {
    BN_free(x); BN_free(y);
    EC_POINT_free(point);
    EC_KEY_free(key);
    return false;
  }

  if (EC_KEY_set_public_key(key, point) != 1) {
    BN_free(x); BN_free(y);
    EC_POINT_free(point);
    EC_KEY_free(key);
    return false;
  }

  if (EC_POINT_is_on_curve(group, point, nullptr) != 1) {
    BN_free(x); BN_free(y);
    EC_POINT_free(point);
    EC_KEY_free(key);
    return false;
  }

  ECDSA_SIG* sig = ECDSA_SIG_new();
  if (!sig) {
    BN_free(x); BN_free(y);
    EC_POINT_free(point);
    EC_KEY_free(key);
    throw std::runtime_error("ECDSA_SIG_new failed");
  }

  BIGNUM* r = bn_from_32be(r32_be);
  BIGNUM* s = bn_from_32be(s32_be);

  if (ECDSA_SIG_set0(sig, r, s) != 1) {
    BN_free(r); BN_free(s);
    ECDSA_SIG_free(sig);
    BN_free(x); BN_free(y);
    EC_POINT_free(point);
    EC_KEY_free(key);
    throw std::runtime_error("ECDSA_SIG_set0 failed");
  }

  int v = ECDSA_do_verify(digest32.data(), (int)digest32.size(), sig, key);
  ok = (v == 1);

  ECDSA_SIG_free(sig);
  BN_free(x); BN_free(y);
  EC_POINT_free(point);
  EC_KEY_free(key);
  return ok;
}

// Result of normalization (what to actually use in Longfellow)
struct EcdsaNormalizeResult {
  std::vector<uint8_t> pkx;
  std::vector<uint8_t> pky;
  std::vector<uint8_t> e;
  std::vector<uint8_t> r;
  std::vector<uint8_t> s;
  std::string note;
};

// Brute-force common endian bugs across pkx,pky,e,r,s.
// Returns normalized bytes (the first variant that verifies).
static inline EcdsaNormalizeResult normalize_ecdsa_inputs_p256(
    const std::vector<uint8_t>& pkx_in,
    const std::vector<uint8_t>& pky_in,
    const std::vector<uint8_t>& e_in,
    const std::vector<uint8_t>& r_in,
    const std::vector<uint8_t>& s_in
) {
  require_32(pkx_in, "pkx");
  require_32(pky_in, "pky");
  require_32(e_in,   "e");
  require_32(r_in,   "r");
  require_32(s_in,   "s");

  struct Variant {
    bool rev_pk;
    bool rev_e;
    bool rev_r;
    bool rev_s;
    const char* note;
  };

  // Ordered: try "as-provided" first, then minimal flips, then heavier flips.
  static const Variant vars[] = {
    {false,false,false,false,"OK (pk,e,r,s big-endian)"},
    {false,false,true ,true ,"OK (r,s little-endian)"},
    {false,true ,false,false,"OK (e little-endian)"},
    {false,true ,true ,true ,"OK (e,r,s little-endian)"},
    {true ,false,false,false,"OK (pkx,pky little-endian)"},
    {true ,false,true ,true ,"OK (pkx,pky,r,s little-endian)"},
    {true ,true ,false,false,"OK (pkx,pky,e little-endian)"},
    {true ,true ,true ,true ,"OK (pkx,pky,e,r,s little-endian)"},
  };

  for (const auto& v : vars) {
    std::vector<uint8_t> pkx = v.rev_pk ? rev32(pkx_in) : pkx_in;
    std::vector<uint8_t> pky = v.rev_pk ? rev32(pky_in) : pky_in;
    std::vector<uint8_t> e   = v.rev_e  ? rev32(e_in)   : e_in;
    std::vector<uint8_t> r   = v.rev_r  ? rev32(r_in)   : r_in;
    std::vector<uint8_t> s   = v.rev_s  ? rev32(s_in)   : s_in;

    if (openssl_verify_p256_sig(pkx, pky, e, r, s)) {
      return {pkx, pky, e, r, s, v.note};
    }
  }

  throw std::runtime_error(
      "ECDSA signature does NOT verify under P-256 for common endianness fixes.\n"
      "So either pkx/pky/e/r/s don't match, or e is not the digest you think it is."
  );
}