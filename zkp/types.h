#pragma once
#include <vector>
#include <cstdint>

namespace zkp {

struct PublicInputs {
    std::vector<uint8_t> data;
};

struct Proof {
    std::vector<uint8_t> data;
};

struct ProofInput {
    std::vector<uint8_t> supplierPK;
    std::vector<uint8_t> signature;
    uint64_t timestamp;
    std::vector<uint8_t> nonce;
};

struct EcdsaProofInput {
    // public:
    std::vector<uint8_t> pkx_32; // 32 bytes big-endian
    std::vector<uint8_t> pky_32; // 32 bytes big-endian
    std::vector<uint8_t> e_32;   // 32 bytes big-endian (sha256 digest or scalar bytes)

    // private (witness-generating):
    std::vector<uint8_t> r_32;
    std::vector<uint8_t> s_32;
};

} // namespace zkp
