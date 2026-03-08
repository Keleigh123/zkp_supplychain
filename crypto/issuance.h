#pragma once
#include <vector>
#include <cstdint>
#include <string>

struct Credential {
    std::vector<uint8_t> r32;    // 32 bytes BE
    std::vector<uint8_t> s32;    // 32 bytes BE
    std::vector<uint8_t> nonce;  // 32 bytes
    std::vector<uint8_t> e32;   
    uint64_t timestamp;

    Credential(std::vector<uint8_t>&& r,
               std::vector<uint8_t>&& s,
               std::vector<uint8_t>&& n,
               std::vector<uint8_t>&& e,
               uint64_t ts)
        : r32(std::move(r)), s32(std::move(s)), nonce(std::move(n)), e32(std::move(e)),timestamp(ts) {}
};

Credential issue_credential_p256(
    const std::vector<uint8_t>& supplierPK,
    const std::string& chainPK_b64,
    uint64_t timestamp
);