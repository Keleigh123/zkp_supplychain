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

struct EcdsaMerkleProofInput {
    // public
    std::vector<uint8_t> approved_root_32; // 32 bytes

    // private ECDSA inputs
    std::vector<uint8_t> pkx_32; // 32 bytes BE (for parsing into pkx_elt)
    std::vector<uint8_t> pky_32; // 32 bytes BE
    std::vector<uint8_t> e_32;   // 32 bytes BE digest (will be reduced mod n in prover)
    std::vector<uint8_t> r_32;   // 32 bytes BE
    std::vector<uint8_t> s_32;   // 32 bytes BE

    // private Merkle inputs
    std::vector<std::vector<uint8_t>> siblings_32; // D x 32 bytes
    std::vector<uint8_t> dirs;                     // D values 0/1
};

} // namespace zkp
