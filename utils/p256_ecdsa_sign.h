#pragma once
#include <vector>
#include <string>
#include <stdexcept>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

inline std::vector<uint8_t> sha256_openssl(const std::vector<uint8_t>& msg) {
    std::vector<uint8_t> out(32);
    SHA256(msg.data(), msg.size(), out.data());
    return out;
}

inline std::vector<uint8_t> bn_to_32be(const BIGNUM* bn) {
    std::vector<uint8_t> out(32, 0);
    if (BN_bn2binpad(bn, out.data(), (int)out.size()) != (int)out.size()) {
        throw std::runtime_error("BN_bn2binpad failed");
    }
    return out;
}

inline EC_KEY* load_p256_private_key_pem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    if (!bio) throw std::runtime_error("BIO_new_mem_buf failed");
    EC_KEY* key = PEM_read_bio_ECPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!key) throw std::runtime_error("PEM_read_bio_ECPrivateKey failed");

    const EC_GROUP* group = EC_KEY_get0_group(key);
    if (!group || EC_GROUP_get_curve_name(group) != NID_X9_62_prime256v1) {
        EC_KEY_free(key);
        throw std::runtime_error("Not a P-256 private key");
    }
    return key;
}

inline void ecdsa_sign_digest_rs32(EC_KEY* key,
                                  const std::vector<uint8_t>& digest32,
                                  std::vector<uint8_t>& r32,
                                  std::vector<uint8_t>& s32) {
    if (digest32.size() != 32) throw std::runtime_error("digest must be 32 bytes");

    ECDSA_SIG* sig = ECDSA_do_sign(digest32.data(), (int)digest32.size(), key);
    if (!sig) throw std::runtime_error("ECDSA_do_sign failed");

    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);
    if (!r || !s) {
        ECDSA_SIG_free(sig);
        throw std::runtime_error("ECDSA_SIG_get0 failed");
    }

    r32 = bn_to_32be(r);
    s32 = bn_to_32be(s);
    ECDSA_SIG_free(sig);
}