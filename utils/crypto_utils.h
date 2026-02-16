#pragma once
#include <sodium.h>
#include <vector>
#include <string>

inline std::vector<uint8_t> from_base64(const std::string& b64) {
    std::vector<uint8_t> out(b64.size());
    size_t len;

    sodium_base642bin(
        out.data(), out.size(),
        b64.c_str(), b64.size(),
        nullptr, &len, nullptr,
        sodium_base64_VARIANT_ORIGINAL
    );

    out.resize(len);
    return out;
}

inline std::string base64_encode(const uint8_t* data, size_t len) {
    // You can use libsodium:
    size_t out_len = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(out_len, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
    // remove null terminator
    out.resize(strlen(out.c_str()));
    return out;
}

inline std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out(32);
    crypto_hash_sha256(out.data(), data.data(), data.size());
    return out;
}

// -------- URL-SAFE BASE64 (NO PADDING) --------

inline std::vector<uint8_t> from_base64_urlsafe(const std::string& b64) {
    std::vector<uint8_t> out(b64.size());
    size_t len;

    if (sodium_base642bin(
            out.data(), out.size(),
            b64.c_str(), b64.size(),
            nullptr, &len, nullptr,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING
        ) != 0) {
        throw std::runtime_error("Invalid URL-safe base64");
    }

    out.resize(len);
    return out;
}

inline std::string base64_encode_urlsafe(const uint8_t* data, size_t len) {
    size_t out_len =
        sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    std::string out(out_len, '\0');
    sodium_bin2base64(
        out.data(), out.size(),
        data, len,
        sodium_base64_VARIANT_URLSAFE_NO_PADDING
    );

    out.resize(strlen(out.c_str()));
    return out;
}

inline std::string base64_encode_urlsafe(const std::vector<uint8_t>& v) {
    return base64_encode_urlsafe(v.data(), v.size());
}

