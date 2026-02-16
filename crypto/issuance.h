#pragma once
#include <vector>
#include <cstdint>

struct Credential {
    std::vector<uint8_t> signature;
    std::vector<uint8_t> nonce;
    uint64_t timestamp;

    Credential(
        std::vector<uint8_t>&& sig,
        std::vector<uint8_t>&& n,
        uint64_t ts
    )
        : signature(std::move(sig)),
          nonce(std::move(n)),
          timestamp(ts)
    {}
};


Credential issue_credential(
    const std::vector<uint8_t>& supplierPK,
    const std::string& chainPK_b64,  // <- pass Base64 now
    uint64_t timestamp
);

