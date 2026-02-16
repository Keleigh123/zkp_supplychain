#include <sodium.h>
#include <iostream>
#include <vector>

std::string b64(const unsigned char* data, size_t len) {
    size_t b64_len = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL);
    std::vector<char> out(b64_len);
    sodium_bin2base64(out.data(), out.size(), data, len,
                      sodium_base64_VARIANT_ORIGINAL);
    return std::string(out.data());
}

int main() {
    if (sodium_init() < 0) {
    std::cerr << "libsodium init failed\n";
    return 1;
}

    std::cout << "[\n";

    for (int i = 1; i <= 10; i++) {
        unsigned char pk[crypto_sign_PUBLICKEYBYTES];
        unsigned char sk[crypto_sign_SECRETKEYBYTES];

        crypto_sign_keypair(pk, sk);

        std::cout << "  {\n";
        std::cout << "    \"chainName\": \"Chain" << i << "\",\n";
        std::cout << "    \"chainPK\": \"" << b64(pk, sizeof(pk)) << "\",\n";
        std::cout << "    \"chainSK\": \"" << b64(sk, sizeof(sk)) << "\"\n";
        std::cout << "  }" << (i < 10 ? "," : "") << "\n";
    }

    std::cout << "]\n";
}
