#pragma once
#include <string>
#include <stdexcept>

#include "mongo.h"
#include <bsoncxx/builder/stream/document.hpp>

inline std::string get_chain_sk_pem_from_db(const std::string& chainPK_b64) {
    auto db = Mongo::instance().db();
    auto col = db["keypair_p256"];

    auto doc = col.find_one(
        bsoncxx::builder::stream::document{}
            << "chainPK" << chainPK_b64
            << bsoncxx::builder::stream::finalize
    );

    if (!doc) throw std::runtime_error("P-256 chain key not found");

    return doc->view()["chainSK_PEM"].get_utf8().value.to_string();
}