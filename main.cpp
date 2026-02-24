#include <crow.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include "zkp/ecdsa_prover.h"
#include "db/mongo.h"
#include "crypto/issuance.h"
#include "utils/crypto_utils.h"  // for from_base64, base64_encode
#include "zkp/types.h"
#include "zkp/prover.h"
#include "zkp/verifier.h"
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/builder/stream/helpers.hpp>
#include "utils/ecdsa_check.h"
#include "zkp/ecdsa_input_check.h"

using json = nlohmann::json;

// -------------------- Helpers --------------------

// Convert string to MongoDB ObjectId
bsoncxx::oid str2oid(const std::string& id) {
    return bsoncxx::oid{id};
}

// Load approved/revoked chains from JSON file
std::vector<std::vector<uint8_t>> load_chain_set(const std::string& filename) {
    std::ifstream file(filename);
    json j;
    file >> j;
    std::vector<std::vector<uint8_t>> chains;
    for (auto& entry : j) {
        chains.push_back(from_base64(entry["chainPK"].get<std::string>()));
    }
    return chains;
}

// Convert binary data to Base64 string
std::string to_base64(const std::vector<uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}

// -------------------- VK Cache --------------------
// std::unordered_map<std::string, zkp::VerificationKey> vk_cache;
// std::mutex vk_mutex;

// zkp::VerificationKey get_vk_for_circuit(const std::string& circuit_id) {
//     std::lock_guard<std::mutex> lock(vk_mutex);
//     auto it = vk_cache.find(circuit_id);
//     if (it != vk_cache.end()) return it->second;

//     zkp::VerificationKey vk = zkp::generate_vk_only();
//     vk_cache[circuit_id] = vk;
//     return vk;
// }

static void generate_ecdsa_proof_route(const crow::request& req, crow::response& res) {
    json body = json::parse(req.body);

    zkp::EcdsaProofInput in;
    in.pkx_32 = from_base64(body["pkx"].get<std::string>());
    in.pky_32 = from_base64(body["pky"].get<std::string>());
    in.e_32   = from_base64(body["e"].get<std::string>());
    in.r_32   = from_base64(body["r"].get<std::string>());
    in.s_32   = from_base64(body["s"].get<std::string>());

    // Basic sanity
    auto check32 = [](const std::vector<uint8_t>& v, const char* name) {
        if (v.size() != 32) throw std::runtime_error(std::string(name) + " must be 32 bytes");
    };
    check32(in.pkx_32, "pkx");
    check32(in.pky_32, "pky");
    check32(in.e_32,   "e");
    check32(in.r_32,   "r");
    check32(in.s_32,   "s");

  // After check32(...) lines:

// --- Normalize endianness (pk/e/r/s) to the first OpenSSL-verifying interpretation ---
try {
    auto norm = normalize_ecdsa_inputs_p256(
        in.pkx_32, in.pky_32, in.e_32, in.r_32, in.s_32
    );

    std::cerr << "ECDSA normalize: " << norm.note << "\n";

    // overwrite with normalized bytes
    in.pkx_32 = std::move(norm.pkx);
    in.pky_32 = std::move(norm.pky);
    in.e_32   = std::move(norm.e);
    in.r_32   = std::move(norm.r);
    in.s_32   = std::move(norm.s);
} catch (const std::exception& ex) {
    res.code = 400;
    res.write(std::string("Bad ECDSA inputs: ") + ex.what());
    res.end();
    return;
}

// Optional extra check (now that we normalized):
if (!openssl_verify_p256(in.pkx_32, in.pky_32, in.e_32, in.r_32, in.s_32)) {
    res.code = 400;
    res.write("OpenSSL verify failed even after normalization");
    res.end();
    return;
}



    zkp::PublicInputs pub;
    zkp::Proof proof = zkp::generate_ecdsa_proof(in, pub);

    auto db  = Mongo::instance().db();
    auto col = db["zk_proof_ecdsa"];

    bsoncxx::builder::stream::document doc{};
    doc
      << "pkx" << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                          static_cast<uint32_t>(in.pkx_32.size()),
                                          in.pkx_32.data()}
      << "pky" << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                          static_cast<uint32_t>(in.pky_32.size()),
                                          in.pky_32.data()}
      << "e"   << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                          static_cast<uint32_t>(in.e_32.size()),
                                          in.e_32.data()}
      << "r"   << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                          static_cast<uint32_t>(in.r_32.size()),
                                          in.r_32.data()}
      << "s"   << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                          static_cast<uint32_t>(in.s_32.size()),
                                          in.s_32.data()}
      << "proof" << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                            static_cast<uint32_t>(proof.data.size()),
                                            proof.data.data()}
      << "pub"   << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                            static_cast<uint32_t>(pub.data.size()),
                                            pub.data.data()}
      << "status" << "GENERATED";

    col.insert_one(doc.view());

    res.code = 200;
    res.write("ECDSA ZK proof generated and saved.");
    res.end();
}

static void generate_proof_route(const crow::request& req, crow::response& res) {
    json body = json::parse(req.body);

    zkp::ProofInput input;
    input.supplierPK = from_base64(body["supplierPK"].get<std::string>());
    input.signature  = from_base64(body["signature"].get<std::string>());
    input.timestamp  = body["timestamp"].get<uint64_t>();
    input.nonce      = from_base64(body["nonce"].get<std::string>()); //nonce needs to be saved when gen crdential

    std::string supplyRequestId = body["supplyRequestId"].get<std::string>();
   std::vector<uint8_t> verifierChainPK = from_base64(body["chainPK"].get<std::string>());
    zkp::PublicInputs pub;
    zkp::Proof proof = zkp::generate_proof(input, pub);

    auto db  = Mongo::instance().db();
    auto col = db["zk_proof"];

    bsoncxx::builder::stream::document doc{};
    doc
        << "supplierPK"
        << bsoncxx::types::b_binary{
               bsoncxx::binary_sub_type::k_binary,
               static_cast<uint32_t>(input.supplierPK.size()),
               input.supplierPK.data()
           }
        << "signature"
        << bsoncxx::types::b_binary{
               bsoncxx::binary_sub_type::k_binary,
               static_cast<uint32_t>(input.signature.size()),
               input.signature.data()
           }
        << "nonce"
        << bsoncxx::types::b_binary{
               bsoncxx::binary_sub_type::k_binary,
               static_cast<uint32_t>(input.nonce.size()),
               input.nonce.data()
           }
        << "timestamp" << static_cast<int64_t>(input.timestamp)
        << "supplyRequestId" << str2oid(supplyRequestId)
           << "verifierChainPK" << bsoncxx::types::b_binary{
               bsoncxx::binary_sub_type::k_binary,
               static_cast<uint32_t>(verifierChainPK.size()),
               verifierChainPK.data()
           }
        << "proof"
        << bsoncxx::types::b_binary{
               bsoncxx::binary_sub_type::k_binary,
               static_cast<uint32_t>(proof.data.size()),
               proof.data.data()
           }
        << "pub"
        << bsoncxx::types::b_binary{
               bsoncxx::binary_sub_type::k_binary,
               static_cast<uint32_t>(pub.data.size()),
               pub.data.data()
           }
        << "status" << "GENERATED";

    col.insert_one(doc.view());

    res.code = 200;
    res.write("Proof generated and saved successfully.");
    res.end();
}

// =================================================
// =============== PROOF VERIFICATION ===============
// =================================================

static void verify_proof_route(crow::response& res, std::string id) {
    auto db = Mongo::instance().db();
    auto proofCol  = db["zk_proof"];
    auto supplyCol = db["supply_requests"];

    auto maybeDoc = proofCol.find_one(
        bsoncxx::builder::stream::document{}
            << "_id" << str2oid(id)
            << bsoncxx::builder::stream::finalize
    );

    if (!maybeDoc) {
        res.code = 404;
        res.write("Proof not found");
        res.end();
        return;
    }

    auto doc = maybeDoc->view();

    // ----------------- Load stored data -----------------

    zkp::Proof proof;
    proof.data.assign(
        doc["proof"].get_binary().bytes,
        doc["proof"].get_binary().bytes + doc["proof"].get_binary().size
    );

    zkp::PublicInputs pub;
    pub.data.assign(
        doc["pub"].get_binary().bytes,
        doc["pub"].get_binary().bytes + doc["pub"].get_binary().size
    );

    auto supplierPK = std::vector<uint8_t>(
        doc["supplierPK"].get_binary().bytes,
        doc["supplierPK"].get_binary().bytes + doc["supplierPK"].get_binary().size
    );

    auto signature = std::vector<uint8_t>(
        doc["signature"].get_binary().bytes,
        doc["signature"].get_binary().bytes + doc["signature"].get_binary().size
    );

    auto nonce = std::vector<uint8_t>(
        doc["nonce"].get_binary().bytes,
        doc["nonce"].get_binary().bytes + doc["nonce"].get_binary().size
    );

    uint64_t ts = static_cast<uint64_t>(doc["timestamp"].get_int64());

    // ----------------- Recompute digest -----------------

    std::vector<uint8_t> msg;
    msg.insert(msg.end(), supplierPK.begin(), supplierPK.end());

    for (int i = 0; i < 8; i++)
        msg.push_back((ts >> (8 * i)) & 0xff);

    msg.insert(msg.end(), nonce.begin(), nonce.end());

    std::vector<uint8_t> recomputed_pub = sha256(msg);

    if (recomputed_pub != pub.data) {
        res.code = 400;
        res.write("Public input mismatch (tampered data)");
        res.end();
        return;
    }

    // ----------------- ZK verification -----------------

    if (!zkp::verify_proof(proof, pub)) {
        res.code = 400;
        res.write("Invalid ZK proof");
        res.end();
        return;
    }

    // ----------------- WI signature check -----------------

    auto approved = load_chain_set("/home/keleigh/zkp-service/approved_set.json");

    bool sig_ok = false;
    for (const auto& pk : approved) {
        if (crypto_sign_verify_detached(
                signature.data(),
                msg.data(),
                msg.size(),
                pk.data()
            ) == 0) {
            sig_ok = true;
            break;
        }
    }

    if (!sig_ok) {
        res.code = 403;
        res.write("Signature not from approved chain");
        res.end();
        return;
    }

    // ----------------- Persist result -----------------

    proofCol.update_one(
        bsoncxx::builder::stream::document{}
            << "_id" << str2oid(id)
            << bsoncxx::builder::stream::finalize,
        bsoncxx::builder::stream::document{}
            << "$set" << bsoncxx::builder::stream::open_document
            << "verified" << true
            << "status"   << "VERIFIED"
            << bsoncxx::builder::stream::close_document
            << bsoncxx::builder::stream::finalize
    );

    auto supplyRequestOid = doc["supplyRequestId"].get_oid().value;
    supplyCol.update_one(
        bsoncxx::builder::stream::document{}
            << "_id" << supplyRequestOid
            << bsoncxx::builder::stream::finalize,
        bsoncxx::builder::stream::document{}
            << "$set" << bsoncxx::builder::stream::open_document
            << "status" << "ACKNOWLEDGED"
            << bsoncxx::builder::stream::close_document
            << bsoncxx::builder::stream::finalize
    );

    json j;
    j["verified"] = true;
    res.write(j.dump());
    res.end();
}

// -------------------- Main --------------------
int main() {
    crow::SimpleApp app;

    // 1️⃣ Get approved chains
    CROW_ROUTE(app, "/approvedChains").methods("GET"_method)
    ([](const crow::request&, crow::response& res){
        auto approved = load_chain_set("/home/keleigh/zkp-service/approved_set.json");
        json j = json::array();
        for (auto& pk : approved) j.push_back(to_base64(pk));
        res.write(j.dump());
        res.end();
    });

    // 2️⃣ Supplier submits a supply request
    CROW_ROUTE(app, "/supplyRequests").methods("POST"_method)
    ([](const crow::request& req, crow::response& res){
        auto body = json::parse(req.body);
        auto db = Mongo::instance().db();
        auto col = db["supply_requests"];

        std::vector<uint8_t> supplierPK = from_base64(body["supplierPK"].get<std::string>());
        std::vector<uint8_t> targetChainPK = from_base64(body["targetChainPK"].get<std::string>());

bsoncxx::builder::stream::document doc{};

        doc << "supplierPK" << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                                         static_cast<uint32_t>(supplierPK.size()), supplierPK.data()}
            << "targetChainPK" << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                                            static_cast<uint32_t>(targetChainPK.size()), targetChainPK.data()}
            << "status" << "PENDING";

        col.insert_one(doc.view());
        res.code = 200; res.end();
    });

    CROW_ROUTE(app, "/supplyRequests/pending").methods("GET"_method)
([](const crow::request& req, crow::response& res){
    auto chainPK_b64 = req.url_params.get("chainPK");
    if (!chainPK_b64) { res.code = 400; res.end("Missing chainPK"); return; }

    auto db = Mongo::instance().db();
    auto col = db["supply_requests"];
    std::vector<uint8_t> chainPK = from_base64(chainPK_b64);

    bsoncxx::builder::stream::document filter{};
    filter << "targetChainPK" << bsoncxx::types::b_binary{
                  bsoncxx::binary_sub_type::k_binary,
                  static_cast<uint32_t>(chainPK.size()), chainPK.data()
              }
           << "status" << "PENDING";

    json j = json::array();
    for (auto&& doc : col.find(filter.view())) {
        json item;
        item["_id"] = doc["_id"].get_oid().value.to_string();
        item["supplierPK"] = to_base64(std::vector<uint8_t>(
            doc["supplierPK"].get_binary().bytes,
            doc["supplierPK"].get_binary().bytes + doc["supplierPK"].get_binary().size
        ));
        item["status"] = doc["status"].get_string().value.to_string();
        j.push_back(item);
    }
    res.write(j.dump()); res.end();
});

    // 4️⃣ Mark supply request as proof requested
    CROW_ROUTE(app, "/supplyRequests/<string>/requestProof").methods("PUT"_method)
    ([](const crow::request&, crow::response& res, std::string id){
        auto db = Mongo::instance().db();
        auto col = db["supply_requests"];

        bsoncxx::builder::stream::document filter{};
        filter << "_id" << str2oid(id);
        bsoncxx::builder::stream::document update{};
        update << "$set" << bsoncxx::builder::stream::open_document
               << "status" << "PROOF_REQUESTED"
               << bsoncxx::builder::stream::close_document;

        col.update_one(filter.view(), update.view());
        res.code = 200; res.end();
    });

    // 5️⃣ Supplier requests a credential
    CROW_ROUTE(app, "/credentials/request").methods("POST"_method)
    ([](const crow::request& req, crow::response& res){
        auto body = json::parse(req.body);
        auto db = Mongo::instance().db();
        auto col = db["issuecred_requests"];

        std::vector<uint8_t> supplierPK = from_base64(body["supplierPK"].get<std::string>());
        std::vector<uint8_t> pastChainPK = from_base64(body["pastChainPK"].get<std::string>());

bsoncxx::builder::stream::document doc{};

        doc << "supplierPK" << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                                        static_cast<uint32_t>(supplierPK.size()), supplierPK.data()}
            << "pastChainPK" << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                                           static_cast<uint32_t>(pastChainPK.size()), pastChainPK.data()}
            << "status" << "PENDING";

        col.insert_one(doc.view());
        res.code = 200; res.end();
    });

    // 6️⃣ Get pending credential requests for a chain
   CROW_ROUTE(app, "/credissueRequests/pending").methods("GET"_method)
([](const crow::request& req, crow::response& res){
    auto chainPK_b64 = req.url_params.get("chainPK");
    if (!chainPK_b64) {
        res.code = 400;
        res.end("Missing chainPK");
        return;
    }
        auto db = Mongo::instance().db();
        auto col = db["issuecred_requests"];
        std::vector<uint8_t> chainPK = from_base64(chainPK_b64);

        bsoncxx::builder::stream::document filter{};
        filter << "pastChainPK" << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                                              static_cast<uint32_t>(chainPK.size()), chainPK.data()}
               << "status" << "PENDING";

        json j = json::array();
        for (auto&& doc : col.find(filter.view())) {
            json item;
            item["_id"] = doc["_id"].get_oid().value.to_string();
            item["supplierPK"] = to_base64(std::vector<uint8_t>(
                doc["supplierPK"].get_binary().bytes,
                doc["supplierPK"].get_binary().bytes + doc["supplierPK"].get_binary().size
            ));
            item["status"] = doc["status"].get_string().value.to_string();
            j.push_back(item);
        }
        res.write(j.dump()); res.end();
    });

    // 7️⃣ Chain issues a credential
    CROW_ROUTE(app, "/credentials/issue/<string>").methods("PUT"_method)
    ([](const crow::request& req, crow::response& res, std::string id){
        auto db = Mongo::instance().db();
        auto col = db["issuecred_requests"];
        auto body = json::parse(req.body);

        std::vector<uint8_t> supplierPK = from_base64(body["supplierPK"].get<std::string>());
        // Instead of decoding Base64, just pass it directly
       std::string chainPK_b64 = body["chainPK"].get<std::string>();

        uint64_t ts = body["timestamp"].get<uint64_t>();

      auto cred = issue_credential_p256(supplierPK, chainPK_b64, ts);

bsoncxx::builder::stream::document update{};
update << "$set" << bsoncxx::builder::stream::open_document
       << "status" << "ISSUED"
       << "credential_r"
       << bsoncxx::types::b_binary{
            bsoncxx::binary_sub_type::k_binary,
            static_cast<uint32_t>(cred.r32.size()),
            cred.r32.data()
          }
       << "credential_s"
       << bsoncxx::types::b_binary{
            bsoncxx::binary_sub_type::k_binary,
            static_cast<uint32_t>(cred.s32.size()),
            cred.s32.data()
          }
       << "credential_nonce"
       << bsoncxx::types::b_binary{
            bsoncxx::binary_sub_type::k_binary,
            static_cast<uint32_t>(cred.nonce.size()),
            cred.nonce.data()
          }
       << "timestamp" << static_cast<int64_t>(cred.timestamp)
       << bsoncxx::builder::stream::close_document;

       col.update_one(
    bsoncxx::builder::stream::document{} << "_id" << str2oid(id) << bsoncxx::builder::stream::finalize,
    update.view()
);

        res.code = 200; res.end();
    });

   
   // 8️⃣ Get all issued credentials for a supplier
CROW_ROUTE(app, "/allissuedcredentials").methods("GET"_method)
([](const crow::request& req, crow::response& res){
    auto supplierPK_b64 = req.url_params.get("supplierPK");
    if (!supplierPK_b64) {
        res.code = 400;
        res.end("Missing supplierPK");
        return;
    }

    std::vector<uint8_t> supplierPK = from_base64(supplierPK_b64);

    auto db = Mongo::instance().db();
    auto col = db["issuecred_requests"];

    bsoncxx::builder::stream::document filter{};
    filter << "supplierPK"
           << bsoncxx::types::b_binary{
                bsoncxx::binary_sub_type::k_binary,
                static_cast<uint32_t>(supplierPK.size()),
                supplierPK.data()
              }
           << "status" << "ISSUED";

    json j = json::array();

    for (auto&& doc : col.find(filter.view())) {
        json item;
        item["_id"] = doc["_id"].get_oid().value.to_string();
        item["timestamp"] = static_cast<int64_t>(doc["timestamp"].get_int64());

        // r (32 bytes)
        if (doc["credential_r"] && doc["credential_r"].type() == bsoncxx::type::k_binary) {
            auto bin = doc["credential_r"].get_binary();
            item["credential_r"] = to_base64(std::vector<uint8_t>(
                bin.bytes, bin.bytes + bin.size
            ));
        } else {
            item["credential_r"] = nullptr;
        }

        // s (32 bytes)
        if (doc["credential_s"] && doc["credential_s"].type() == bsoncxx::type::k_binary) {
            auto bin = doc["credential_s"].get_binary();
            item["credential_s"] = to_base64(std::vector<uint8_t>(
                bin.bytes, bin.bytes + bin.size
            ));
        } else {
            item["credential_s"] = nullptr;
        }

        // nonce (32 bytes)
        if (doc["credential_nonce"] && doc["credential_nonce"].type() == bsoncxx::type::k_binary) {
            auto bin = doc["credential_nonce"].get_binary();
            item["credential_nonce"] = to_base64(std::vector<uint8_t>(
                bin.bytes, bin.bytes + bin.size
            ));
        } else {
            item["credential_nonce"] = nullptr;
        }

        // chainPK (pastChainPK stored as binary)
        if (doc["pastChainPK"] && doc["pastChainPK"].type() == bsoncxx::type::k_binary) {
            auto bin = doc["pastChainPK"].get_binary();
            item["chainPK"] = to_base64(std::vector<uint8_t>(
                bin.bytes, bin.bytes + bin.size
            ));
        } else {
            item["chainPK"] = nullptr;
        }

        j.push_back(std::move(item));
    }

    res.set_header("Content-Type", "application/json");
    res.write(j.dump());
    res.end();
});
    // 9️⃣ Generate ZK proof
CROW_ROUTE(app, "/proofs/generate").methods("POST"_method)
([&app](const crow::request& req, crow::response& res){
    try {
        generate_proof_route(req, res);  // No app needed here
    } catch (const std::exception& e) {
        res.code = 400;
        res.write(std::string("Error: ") + e.what());
        res.end();
    }
});


    // 🔟 Get proofs to verify for a chain
   CROW_ROUTE(app, "/proofstoverify").methods("GET"_method)
([](const crow::request& req, crow::response& res){
    auto chainPK_b64 = req.url_params.get("chainPK");
    if (!chainPK_b64) { res.code = 400; res.end("Missing chainPK"); return; }

        auto db = Mongo::instance().db();
        auto col = db["zk_proof"];
        std::vector<uint8_t> chainPK = from_base64(chainPK_b64);

        bsoncxx::builder::stream::document filter{};
        filter << "verifierChainPK" << bsoncxx::types::b_binary{bsoncxx::binary_sub_type::k_binary,
                                                               static_cast<uint32_t>(chainPK.size()), chainPK.data()}
               << "status" << "GENERATED";

        json j = json::array();
        for (auto&& doc : col.find(filter.view())) {
            json item;
            item["_id"] = doc["_id"].get_oid().value.to_string();
            item["supplierPK"] = to_base64(std::vector<uint8_t>(
                doc["supplierPK"].get_binary().bytes,
                doc["supplierPK"].get_binary().bytes + doc["supplierPK"].get_binary().size
            ));
            j.push_back(item);
        }
        res.write(j.dump()); res.end();
    });

    // 1️⃣1️⃣ Verify a proof
CROW_ROUTE(app, "/proofs/<string>/verify").methods("POST"_method)
([&app](const crow::request&, crow::response& res, std::string id){
    try {
        verify_proof_route(res, id);  // ✅ Now app is captured by reference
    } catch (const std::exception& e) {
        res.code = 400;
        res.write(std::string("Error: ") + e.what());
        res.end();
    }
});

CROW_ROUTE(app, "/proofs/generateEcdsa").methods("POST"_method)
([](const crow::request& req, crow::response& res){
    try {
        std::cerr << "About to call generate_ecdsa_proof...\n";
        generate_ecdsa_proof_route(req, res);
    } catch (const std::exception& e) {
        std::cerr << "[generateEcdsa] exception: " << e.what() << "\n";
        res.code = 400;
        res.set_header("Content-Type", "text/plain");
        res.write(std::string("Error: ") + e.what());
        res.end();
    }
});

    app.port(8080).multithreaded().run();
}
