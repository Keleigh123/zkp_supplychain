#pragma once
#include <vector>
#include <string>
#include "mongo.h"
#include "../utils/crypto_utils.h"
#include <bsoncxx/builder/stream/document.hpp>
#include <stdexcept>

inline std::vector<uint8_t> get_chain_sk_from_db(
    const std::string& chainPK_b64
) {
    auto db = Mongo::instance().db();
    auto col = db["keypair"];

    auto doc = col.find_one(
        bsoncxx::builder::stream::document{}
            << "chainPK" << chainPK_b64
            << bsoncxx::builder::stream::finalize
    );

    if (!doc) {
        throw std::runtime_error("Chain key not found");
    }

    auto sk_b64 = doc->view()["chainSK"].get_utf8().value.to_string();
    return from_base64(sk_b64);
}

