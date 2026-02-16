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

} // namespace zkp
