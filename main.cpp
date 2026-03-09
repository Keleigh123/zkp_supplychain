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
#include "zkp/ecdsa_merkle_prover.h"
#include <iostream>
#include "zkp/ecdsa_merkle_verifier.h"
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
static void verify_ecdsa_approved_proof_route(const crow::request& req, crow::response& res, std::string id) {
    auto db = Mongo::instance().db();
    auto proofCol = db["zk_proof_ecdsa_approved"];
    auto supplyReqCol = db["supply_requests"];

    auto maybeDoc = proofCol.find_one(
        bsoncxx::builder::stream::document{}
            << "_id" << str2oid(id)
            << bsoncxx::builder::stream::finalize
    );

    if (!maybeDoc) {
        res.code = 404;
        res.write("ECDSA approved proof not found");
        res.end();
        return;
    }

    auto doc = maybeDoc->view();

    // Optional verifier authorization check
    std::vector<uint8_t> callerVerifierPK;
    bool checkVerifier = false;

    if (!req.body.empty()) {
        auto body = json::parse(req.body);
        if (body.contains("verifierPK")) {
            callerVerifierPK = from_base64(body["verifierPK"].get<std::string>());
            checkVerifier = true;
        }
    }

    if (checkVerifier) {
        if (!doc["requestedVerifierPK"] || doc["requestedVerifierPK"].type() != bsoncxx::type::k_binary) {
            res.code = 400;
            res.write("Stored proof is missing requestedVerifierPK");
            res.end();
            return;
        }

        std::vector<uint8_t> requestedVerifierPK(
            doc["requestedVerifierPK"].get_binary().bytes,
            doc["requestedVerifierPK"].get_binary().bytes + doc["requestedVerifierPK"].get_binary().size
        );

        if (callerVerifierPK != requestedVerifierPK) {
            res.code = 403;
            res.write("Verifier public key does not match requested verifier");
            res.end();
            return;
        }
    }

    if (!doc["proof"] || doc["proof"].type() != bsoncxx::type::k_binary) {
        res.code = 400;
        res.write("Stored proof bytes missing");
        res.end();
        return;
    }

    if (!doc["pub"] || doc["pub"].type() != bsoncxx::type::k_binary) {
        res.code = 400;
        res.write("Stored public inputs missing");
        res.end();
        return;
    }

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

    bool ok = zkp::verify_ecdsa_merkle_proof(proof, pub);

    if (!ok) {
        proofCol.update_one(
            bsoncxx::builder::stream::document{}
                << "_id" << str2oid(id)
                << bsoncxx::builder::stream::finalize,
            bsoncxx::builder::stream::document{}
                << "$set" << bsoncxx::builder::stream::open_document
                << "status" << "INVALID - verification failed"
                << bsoncxx::builder::stream::close_document
                << bsoncxx::builder::stream::finalize
        );

        res.code = 400;
        res.write("Invalid ECDSA approved ZK proof");
        res.end();
        return;
    }

    proofCol.update_one(
        bsoncxx::builder::stream::document{}
            << "_id" << str2oid(id)
            << bsoncxx::builder::stream::finalize,
        bsoncxx::builder::stream::document{}
            << "$set" << bsoncxx::builder::stream::open_document
            << "status" << "Proof VERIFIED"
            << bsoncxx::builder::stream::close_document
            << bsoncxx::builder::stream::finalize
    );
      if (doc["supplyRequestId"] && doc["supplyRequestId"].type() == bsoncxx::type::k_oid) {
        auto supplyRequestOid = doc["supplyRequestId"].get_oid().value;

        supplyReqCol.update_one(
            bsoncxx::builder::stream::document{}
                << "_id" << supplyRequestOid
                << bsoncxx::builder::stream::finalize,
            bsoncxx::builder::stream::document{}
                << "$set" << bsoncxx::builder::stream::open_document
                << "status" << "ACKNOWLEDGED"
                << bsoncxx::builder::stream::close_document
                << bsoncxx::builder::stream::finalize
        );
    }
    json out;
    out["verified"] = true;
    out["proofId"] = id;

    // optional fields in response
    if (doc["supplyRequestId"] && doc["supplyRequestId"].type() == bsoncxx::type::k_oid) {
        out["supplyRequestId"] = doc["supplyRequestId"].get_oid().value.to_string();
    }

    res.code = 200;
    res.set_header("Content-Type", "application/json");
    res.write(out.dump());
    res.end();
}


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
std::string chainPK_b64_str = chainPK_b64;
    std::replace(chainPK_b64_str.begin(), chainPK_b64_str.end(), ' ', '+');


    auto db = Mongo::instance().db();
    auto col = db["supply_requests"];
    std::vector<uint8_t> chainPK = from_base64(chainPK_b64_str);

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
    std::string chainPK_b64_str = chainPK_b64;
    std::replace(chainPK_b64_str.begin(), chainPK_b64_str.end(), ' ', '+');
        auto db = Mongo::instance().db();
        auto col = db["issuecred_requests"];
        std::vector<uint8_t> chainPK = from_base64(chainPK_b64_str);

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
           << "credential_e" << bsoncxx::types::b_binary{ bsoncxx::binary_sub_type::k_binary,   // <--- add
            static_cast<uint32_t>(cred.e32.size()), cred.e32.data() }    
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
    std::string supplierPK_b64_str = supplierPK_b64;
    std::replace(supplierPK_b64_str.begin(), supplierPK_b64_str.end(), ' ', '+');
    std::vector<uint8_t> supplierPK = from_base64(supplierPK_b64_str);

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

        //e digest
          if (doc["credential_e"] && doc["credential_e"].type() == bsoncxx::type::k_binary) {
            auto bin = doc["credential_e"].get_binary();
            item["credential_e"] = to_base64(std::vector<uint8_t>(
                bin.bytes, bin.bytes + bin.size
            ));
        } else {
            item["credential_e"] = nullptr;
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
  #include <algorithm>
#include <iostream>

CROW_ROUTE(app, "/proofstoverify").methods("GET"_method)
([](const crow::request& req, crow::response& res){
    try {
        auto chainPK_b64 = req.url_params.get("chainPK");
        if (!chainPK_b64) {
            res.code = 400;
            res.end("Missing chainPK");
            return;
        }

        std::string chainPK_b64_str = chainPK_b64;
        std::replace(chainPK_b64_str.begin(), chainPK_b64_str.end(), ' ', '+');

        auto db = Mongo::instance().db();
        auto col = db["zk_proof_ecdsa_approved"];

        std::vector<uint8_t> chainPK = from_base64(chainPK_b64_str);

        bsoncxx::builder::stream::document filter{};
        filter << "requestedVerifierPK" << bsoncxx::types::b_binary{
                    bsoncxx::binary_sub_type::k_binary,
                    static_cast<uint32_t>(chainPK.size()),
                    chainPK.data()
                 }
               << "status" << "ISSUED";

        json j = json::array();

        for (auto&& doc : col.find(filter.view())) {
            json item;

            if (doc["_id"] && doc["_id"].type() == bsoncxx::type::k_oid) {
                item["_id"] = doc["_id"].get_oid().value.to_string();
            }

            if (doc["supplyRequestId"] && doc["supplyRequestId"].type() == bsoncxx::type::k_binary) {
                auto bin = doc["supplyRequestId"].get_binary();
                item["supplyRequestId"] = to_base64(std::vector<uint8_t>(
                    bin.bytes,
                    bin.bytes + bin.size
                )); } else {
                item["supplyRequestId"] = nullptr;
            }

            if (doc["proof"] && doc["proof"].type() == bsoncxx::type::k_binary) {
                auto bin = doc["proof"].get_binary();
                item["proof"] = to_base64(std::vector<uint8_t>(
                    bin.bytes,
                    bin.bytes + bin.size
                ));
            } else {
                item["proof"] = nullptr;
            }

            if (doc["pub"] && doc["pub"].type() == bsoncxx::type::k_binary) {
                auto bin = doc["pub"].get_binary();
                item["pub"] = to_base64(std::vector<uint8_t>(
                    bin.bytes,
                    bin.bytes + bin.size
                ));
            } else {
                item["pub"] = nullptr;
            }

            j.push_back(item);
        }

        res.code = 200;
        res.set_header("Content-Type", "application/json");
        res.write(j.dump());
        res.end();
    } catch (const std::exception& e) {
        std::cerr << "Error in /proofstoverify: " << e.what() << "\n";
        res.code = 500;
        res.end(std::string("Internal server error: ") + e.what());
    }
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

CROW_ROUTE(app, "/proofs/generateEcdsaApproved").methods("POST"_method)
([](const crow::request& req, crow::response& res){
  try {
    auto body = json::parse(req.body);

    auto require = [&](const char* k) {
      if (!body.contains(k)) throw std::runtime_error(std::string("missing key: ") + k);
    };

    require("approved_root");
    require("pkx");
    require("pky");
    require("e");
    require("r");
    require("s");
    require("path_dirs");
    require("path_siblings");
    require("requestedVerifierPK");
    require("supplyRequestId");


    zkp::EcdsaMerkleProofInput in;
    in.approved_root_32 = from_base64(body["approved_root"].get<std::string>());
    in.pkx_32 = from_base64(body["pkx"].get<std::string>());
    in.pky_32 = from_base64(body["pky"].get<std::string>());
    in.e_32   = from_base64(body["e"].get<std::string>());
    in.r_32   = from_base64(body["r"].get<std::string>());
    in.s_32   = from_base64(body["s"].get<std::string>());

    try {
      auto norm = normalize_ecdsa_inputs_p256(
          in.pkx_32, in.pky_32, in.e_32, in.r_32, in.s_32
      );
      std::cerr << "ECDSA normalize(approved): " << norm.note << "\n";

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

    if (!openssl_verify_p256(in.pkx_32, in.pky_32, in.e_32, in.r_32, in.s_32)) {
      res.code = 400;
      res.write("OpenSSL verify failed even after normalization");
      res.end();
      return;
    }

    in.dirs = body["path_dirs"].get<std::vector<uint8_t>>();
    auto sibs = body["path_siblings"].get<std::vector<std::string>>();

    if (in.dirs.empty()) throw std::runtime_error("path_dirs is empty");
    if (sibs.empty())    throw std::runtime_error("path_siblings is empty");

    in.siblings_32.clear();
    for (auto& s : sibs) in.siblings_32.push_back(from_base64(s));

    zkp::PublicInputs pub;
    std::cerr << "sizes: root=" << in.approved_root_32.size()
              << " pkx=" << in.pkx_32.size()
              << " pky=" << in.pky_32.size()
              << " e=" << in.e_32.size()
              << " r=" << in.r_32.size()
              << " s=" << in.s_32.size()
              << " siblings=" << in.siblings_32.size()
              << " dirs=" << in.dirs.size()
              << "\n";

    for (size_t i = 0; i < in.siblings_32.size(); i++) {
      std::cerr << " sibling[" << i << "] size=" << in.siblings_32[i].size() << "\n";
    }

    zkp::Proof proof = zkp::generate_ecdsa_merkle_proof(in, pub);

    auto db  = Mongo::instance().db();
    auto col = db["zk_proof_ecdsa_approved"];

   
    std::vector<uint8_t> requestedVerifierPK =
        from_base64(body["requestedVerifierPK"].get<std::string>());
    std::string supplyRequestIdStr =
    body["supplyRequestId"].get<std::string>();
    bsoncxx::oid supplyRequestOid(supplyRequestIdStr);

    bsoncxx::builder::stream::document doc{};

    doc
      << "approved_root" << bsoncxx::types::b_binary{
            bsoncxx::binary_sub_type::k_binary,
            static_cast<uint32_t>(in.approved_root_32.size()),
            in.approved_root_32.data()
         }
      << "pkx" << bsoncxx::types::b_binary{
            bsoncxx::binary_sub_type::k_binary,
            static_cast<uint32_t>(in.pkx_32.size()),
            in.pkx_32.data()
         }
      << "pky" << bsoncxx::types::b_binary{
            bsoncxx::binary_sub_type::k_binary,
            static_cast<uint32_t>(in.pky_32.size()),
            in.pky_32.data()
         }
      << "e" << bsoncxx::types::b_binary{
            bsoncxx::binary_sub_type::k_binary,
            static_cast<uint32_t>(in.e_32.size()),
            in.e_32.data()
         }
      << "r" << bsoncxx::types::b_binary{
            bsoncxx::binary_sub_type::k_binary,
            static_cast<uint32_t>(in.r_32.size()),
            in.r_32.data()
         }
      << "s" << bsoncxx::types::b_binary{
            bsoncxx::binary_sub_type::k_binary,
            static_cast<uint32_t>(in.s_32.size()),
            in.s_32.data()
         }

      << "sizes" << bsoncxx::builder::stream::open_document
          << "pkx"      << static_cast<int32_t>(in.pkx_32.size())
          << "pky"      << static_cast<int32_t>(in.pky_32.size())
          << "e"        << static_cast<int32_t>(in.e_32.size())
          << "r"        << static_cast<int32_t>(in.r_32.size())
          << "s"        << static_cast<int32_t>(in.s_32.size())
          << "siblings" << static_cast<int32_t>(in.siblings_32.size())
          << "dirs"     << static_cast<int32_t>(in.dirs.size())
      << bsoncxx::builder::stream::close_document

     << "supplyRequestId" << supplyRequestOid
      << "status" << "ISSUED"
      << "requestedVerifierPK" << bsoncxx::types::b_binary{
            bsoncxx::binary_sub_type::k_binary,
            static_cast<uint32_t>(requestedVerifierPK.size()),
            requestedVerifierPK.data()
         }
      << "pub" << bsoncxx::types::b_binary{
            bsoncxx::binary_sub_type::k_binary,
            static_cast<uint32_t>(pub.data.size()),
            pub.data.data()
         }
      << "proof" << bsoncxx::types::b_binary{
            bsoncxx::binary_sub_type::k_binary,
            static_cast<uint32_t>(proof.data.size()),
            proof.data.data()
         };

    // path_dirs array
    {
      auto arr = doc << "path_dirs" << bsoncxx::builder::stream::open_array;
      for (auto d : in.dirs) {
        arr << static_cast<int32_t>(d);
      }
      arr << bsoncxx::builder::stream::close_array;
    }

    // path_siblings array
    {
      auto arr = doc << "path_siblings" << bsoncxx::builder::stream::open_array;
      for (const auto& sib : in.siblings_32) {
        arr << bsoncxx::types::b_binary{
          bsoncxx::binary_sub_type::k_binary,
          static_cast<uint32_t>(sib.size()),
          sib.data()
        };
      }
      arr << bsoncxx::builder::stream::close_array;
    }

    auto result = col.insert_one(doc.view());

    json out;
    out["message"] = "ECDSA approved proof generated and saved";
    out["proof"]   = to_base64(proof.data);
    out["pub"]     = to_base64(pub.data);

    if (result && result->inserted_id().type() == bsoncxx::type::k_oid) {
      out["proofId"] = result->inserted_id().get_oid().value.to_string();
    }

    res.code = 200;
    res.set_header("Content-Type", "application/json");
    res.write(out.dump());
    res.end();

  } catch (const std::exception& e) {
    std::cerr << "generateEcdsaApproved exception: " << e.what() << "\n";
    std::cerr << "request body: " << req.body << "\n";
    res.code = 400;
    res.write(std::string("Error: ") + e.what());
    res.end();
  }
});

CROW_ROUTE(app, "/proofs/ecdsaApproved/<string>/verify").methods("POST"_method)
([](const crow::request& req, crow::response& res, std::string id){
    try {
        verify_ecdsa_approved_proof_route(req, res, id);
    } catch (const std::exception& e) {
        res.code = 400;
        res.write(std::string("Error: ") + e.what());
        res.end();
    }
});
    app.port(8080).multithreaded().run();
}
