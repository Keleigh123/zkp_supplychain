#include <iostream>
#include <string>
#include <vector>

#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

#include "../db/mongo.h"
#include "../utils/crypto_utils.h"  // base64_encode
#include <bsoncxx/builder/stream/document.hpp>


static std::vector<uint8_t> bn_to_32be(const BIGNUM* bn) {
    std::vector<uint8_t> out(32, 0);
    if (BN_bn2binpad(bn, out.data(), (int)out.size()) != (int)out.size()) {
        throw std::runtime_error("BN_bn2binpad failed");
    }
    return out;
}

static std::string ec_private_key_to_pem(EC_KEY* key) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) throw std::runtime_error("BIO_new failed");

    if (PEM_write_bio_ECPrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        throw std::runtime_error("PEM_write_bio_ECPrivateKey failed");
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0) {
        BIO_free(bio);
        throw std::runtime_error("BIO_get_mem_data failed");
    }

    std::string pem(data, (size_t)len);
    BIO_free(bio);
    return pem;
}

int main(int argc, char** argv) {
    std::string chainName = (argc >= 2) ? argv[1] : "ChainX";

    // 1) Generate P-256 key
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) throw std::runtime_error("EC_KEY_new_by_curve_name failed");
    if (EC_KEY_generate_key(key) != 1) {
        EC_KEY_free(key);
        throw std::runtime_error("EC_KEY_generate_key failed");
    }

    // 2) Extract pkx,pky
    const EC_GROUP* group = EC_KEY_get0_group(key);
    const EC_POINT* pub   = EC_KEY_get0_public_key(key);

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    if (!ctx || !x || !y) throw std::runtime_error("BN alloc failed");

    if (EC_POINT_get_affine_coordinates(group, pub, x, y, ctx) != 1) {
        throw std::runtime_error("EC_POINT_get_affine_coordinates failed");
    }

    std::vector<uint8_t> pkx = bn_to_32be(x);
    std::vector<uint8_t> pky = bn_to_32be(y);

    BN_free(x); BN_free(y);
    BN_CTX_free(ctx);

    // chainPK identifier = base64(pkx||pky)
    std::vector<uint8_t> pk_concat = pkx;
    pk_concat.insert(pk_concat.end(), pky.begin(), pky.end());
    std::string chainPK_b64 = base64_encode(pk_concat.data(), pk_concat.size());

    // 3) Private key PEM
    std::string sk_pem = ec_private_key_to_pem(key);
    EC_KEY_free(key);

    // 4) Insert into Mongo
    auto db = Mongo::instance().db();
    auto col = db["keypair_p256"];

    bsoncxx::builder::stream::document doc{};
    doc << "chainName" << chainName
        << "chainPK" << chainPK_b64
        << "chainSK_PEM" << sk_pem;

    col.insert_one(doc.view());

    std::cout << "Inserted keypair_p256\n";
    std::cout << "chainName: " << chainName << "\n";
    std::cout << "chainPK_b64 (pkx||pky): " << chainPK_b64 << "\n";
    std::cout << "pkx_b64: " << base64_encode(pkx.data(), pkx.size()) << "\n";
    std::cout << "pky_b64: " << base64_encode(pky.data(), pky.size()) << "\n";
    return 0;
}