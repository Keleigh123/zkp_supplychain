#pragma once
#include <vector>
#include <cstdint>

bool openssl_verify_p256(
    const std::vector<uint8_t>& pkx,
    const std::vector<uint8_t>& pky,
    const std::vector<uint8_t>& e32,
    const std::vector<uint8_t>& r32,
    const std::vector<uint8_t>& s32
);