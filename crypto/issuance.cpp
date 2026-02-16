#include <sodium.h>
#include <vector>
#include <cstdint>
#include "../db/key_store.h"

#include "issuance.h"

Credential issue_credential(
    const std::vector<uint8_t>& supplierPK,
    const std::string& chainPK_b64,
    uint64_t timestamp
) {
    //  Fetch SK internally
    std::vector<uint8_t> chainSK = get_chain_sk_from_db(chainPK_b64);

    std::vector<uint8_t> nonce(32);
    randombytes_buf(nonce.data(), nonce.size());
    // Message = supplierPK || timestamp
    std::vector<uint8_t> msg = supplierPK;
    msg.insert(
        msg.end(),
        reinterpret_cast<const uint8_t*>(&timestamp),
        reinterpret_cast<const uint8_t*>(&timestamp) + sizeof(uint64_t)
    );
     msg.insert(msg.end(), nonce.begin(), nonce.end());

    std::vector<uint8_t> sig(crypto_sign_BYTES);

    crypto_sign_detached(
        sig.data(),
        nullptr,
        msg.data(),
        msg.size(),
        chainSK.data()
    );

    sodium_memzero(chainSK.data(), chainSK.size());
    return { 
        std::move(sig),
        std::move(nonce),
        timestamp };
}
