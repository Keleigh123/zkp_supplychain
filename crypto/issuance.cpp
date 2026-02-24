#include "issuance.h"

#include <sodium.h>
#include <vector>
#include <cstdint>

#include "../db/key_store_p256.h"
#include "../utils/p256_ecdsa_sign.h"

Credential issue_credential_p256(
    const std::vector<uint8_t>& supplierPK,
    const std::string& chainPK_b64,
    uint64_t timestamp
) {
    // Fetch chain SK PEM
    std::string sk_pem = get_chain_sk_pem_from_db(chainPK_b64);

    // nonce
    std::vector<uint8_t> nonce(32);
    randombytes_buf(nonce.data(), nonce.size());

    // msg = supplierPK || timestamp (LE, same as your current code) || nonce
    std::vector<uint8_t> msg = supplierPK;
    msg.insert(
        msg.end(),
        reinterpret_cast<const uint8_t*>(&timestamp),
        reinterpret_cast<const uint8_t*>(&timestamp) + sizeof(uint64_t)
    );
    msg.insert(msg.end(), nonce.begin(), nonce.end());

    // digest
    std::vector<uint8_t> digest = sha256_openssl(msg);

    // sign digest -> r,s
    std::vector<uint8_t> r32, s32;
    EC_KEY* key = load_p256_private_key_pem(sk_pem);
    try {
        ecdsa_sign_digest_rs32(key, digest, r32, s32);
        EC_KEY_free(key);
    } catch (...) {
        EC_KEY_free(key);
        throw;
    }

    // (optional) wipe pem string
    sodium_memzero(sk_pem.data(), sk_pem.size());

    return Credential{ std::move(r32), std::move(s32), std::move(nonce), timestamp };
}