#include "ecdsa_check.h"

#include <stdexcept>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

static void require_32(const std::vector<uint8_t>& v, const char* name) {
    if (v.size() != 32) {
        throw std::runtime_error(std::string(name) + " must be 32 bytes");
    }
}

bool openssl_verify_p256(
    const std::vector<uint8_t>& pkx,
    const std::vector<uint8_t>& pky,
    const std::vector<uint8_t>& e32,
    const std::vector<uint8_t>& r32,
    const std::vector<uint8_t>& s32
) {
    require_32(pkx, "pkx");
    require_32(pky, "pky");
    require_32(e32, "e32");
    require_32(r32, "r32");
    require_32(s32, "s32");

    bool ok = false;

    EC_KEY* key = nullptr;
    EC_GROUP* group = nullptr;
    EC_POINT* pub_point = nullptr;
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_y = nullptr;

    ECDSA_SIG* sig = nullptr;
    BIGNUM* bn_r = nullptr;
    BIGNUM* bn_s = nullptr;

    // Build P-256 key
    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) goto cleanup;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) goto cleanup;

    pub_point = EC_POINT_new(group);
    if (!pub_point) goto cleanup;

    bn_x = BN_bin2bn(pkx.data(), (int)pkx.size(), nullptr);
    bn_y = BN_bin2bn(pky.data(), (int)pky.size(), nullptr);
    if (!bn_x || !bn_y) goto cleanup;

    if (EC_POINT_set_affine_coordinates_GFp(group, pub_point, bn_x, bn_y, nullptr) != 1) {
        goto cleanup;
    }

    if (EC_KEY_set_public_key(key, pub_point) != 1) {
        goto cleanup;
    }

    // Optional sanity: check pubkey is valid on curve
    if (EC_KEY_check_key(key) != 1) {
        goto cleanup;
    }

    // Build signature
    sig = ECDSA_SIG_new();
    if (!sig) goto cleanup;

    bn_r = BN_bin2bn(r32.data(), (int)r32.size(), nullptr);
    bn_s = BN_bin2bn(s32.data(), (int)s32.size(), nullptr);
    if (!bn_r || !bn_s) goto cleanup;

    // ECDSA_SIG_set0 takes ownership of bn_r and bn_s on success
    if (ECDSA_SIG_set0(sig, bn_r, bn_s) != 1) {
        goto cleanup;
    }
    bn_r = nullptr;
    bn_s = nullptr;

    // Verify: e32 is the 32-byte message digest.
    // ECDSA_do_verify returns 1 on success, 0 on bad sig, -1 on error.
    {
        int rc = ECDSA_do_verify(e32.data(), (int)e32.size(), sig, key);
        ok = (rc == 1);
    }

cleanup:
    if (bn_r) BN_free(bn_r);
    if (bn_s) BN_free(bn_s);
    if (sig) ECDSA_SIG_free(sig);

    if (bn_x) BN_free(bn_x);
    if (bn_y) BN_free(bn_y);
    if (pub_point) EC_POINT_free(pub_point);
    if (group) EC_GROUP_free(group);
    if (key) EC_KEY_free(key);

    return ok;
}