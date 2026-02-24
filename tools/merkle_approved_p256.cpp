#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>
#include <cstring>

#include <nlohmann/json.hpp>

#include "../utils/crypto_utils.h" // from_base64 / base64_encode

using json = nlohmann::json;

static std::vector<uint8_t> sha256_64(const std::vector<uint8_t>& a32,
                                      const std::vector<uint8_t>& b32) {
    if (a32.size() != 32 || b32.size() != 32) throw std::runtime_error("sha256_64 expects 32+32");
    std::vector<uint8_t> in;
    in.reserve(64);
    in.insert(in.end(), a32.begin(), a32.end());
    in.insert(in.end(), b32.begin(), b32.end());
    return sha256(in);
}

static bool is_pow2(size_t n) { return n && ((n & (n - 1)) == 0); }

static size_t next_pow2(size_t n) {
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

struct MerklePath {
    std::vector<std::vector<uint8_t>> siblings; // each 32 bytes
    std::vector<int> dirs; // 0 = current is left, 1 = current is right
};

static std::vector<uint8_t> leaf_hash_from_pk(const std::vector<uint8_t>& pkx,
                                              const std::vector<uint8_t>& pky) {
    if (pkx.size() != 32 || pky.size() != 32) throw std::runtime_error("pkx/pky must be 32 bytes");
    std::vector<uint8_t> pre;
    pre.reserve(64);
    pre.insert(pre.end(), pkx.begin(), pkx.end());
    pre.insert(pre.end(), pky.begin(), pky.end());
    return sha256(pre);
}

static std::vector<uint8_t> pad_leaf() {
    std::vector<uint8_t> zeros(64, 0);
    return sha256(zeros);
}

static std::vector<uint8_t> merkle_root(std::vector<std::vector<uint8_t>> leaves32,
                                        std::vector<std::vector<std::vector<uint8_t>>>* levels_out = nullptr) {
    if (leaves32.empty()) throw std::runtime_error("no leaves");
    for (auto& L : leaves32) if (L.size() != 32) throw std::runtime_error("leaf not 32 bytes");

    size_t n = leaves32.size();
    size_t N = is_pow2(n) ? n : next_pow2(n);
    leaves32.reserve(N);

    auto pad = pad_leaf();
    while (leaves32.size() < N) leaves32.push_back(pad);

    std::vector<std::vector<std::vector<uint8_t>>> levels;
    levels.push_back(leaves32);

    while (levels.back().size() > 1) {
        const auto& cur = levels.back();
        std::vector<std::vector<uint8_t>> nxt;
        nxt.reserve(cur.size() / 2);

        for (size_t i = 0; i < cur.size(); i += 2) {
            nxt.push_back(sha256_64(cur[i], cur[i + 1]));
        }
        levels.push_back(std::move(nxt));
    }

    if (levels_out) *levels_out = levels;
    return levels.back()[0];
}

static MerklePath merkle_path_for_index(const std::vector<std::vector<std::vector<uint8_t>>>& levels,
                                        size_t leaf_index) {
    if (levels.empty()) throw std::runtime_error("no levels");
    if (leaf_index >= levels[0].size()) throw std::runtime_error("leaf_index out of range");

    MerklePath path;

    size_t idx = leaf_index;
    for (size_t level = 0; level + 1 < levels.size(); level++) {
        const auto& cur = levels[level];
        size_t sib = (idx ^ 1);

        path.siblings.push_back(cur[sib]);
        path.dirs.push_back((idx & 1) ? 1 : 0); // if idx is odd, current is right

        idx >>= 1;
    }

    return path;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " approved_set_p256.json [chainNameToPath]\n";
        return 1;
    }

    std::string filename = argv[1];
    std::string wantChain = (argc >= 3) ? argv[2] : "";

    std::ifstream f(filename);
    if (!f) throw std::runtime_error("failed to open " + filename);
    json j;
    f >> j;

    struct Entry { std::string name; std::vector<uint8_t> pkx, pky; };
    std::vector<Entry> entries;
    entries.reserve(j.size());

    for (auto& e : j) {
        Entry en;
        en.name = e.value("chainName", "");
        en.pkx  = from_base64(e.at("pkx").get<std::string>());
        en.pky  = from_base64(e.at("pky").get<std::string>());
        if (en.pkx.size() != 32 || en.pky.size() != 32) throw std::runtime_error("pkx/pky must be 32 bytes");
        entries.push_back(std::move(en));
    }
    if (entries.empty()) throw std::runtime_error("approved list empty");

    // Build leaves
    std::vector<std::vector<uint8_t>> leaves;
    leaves.reserve(entries.size());
    for (auto& en : entries) {
        leaves.push_back(leaf_hash_from_pk(en.pkx, en.pky));
    }

    // Compute root + keep levels for path
    std::vector<std::vector<std::vector<uint8_t>>> levels;
    auto root = merkle_root(leaves, &levels);

    std::cout << "approved_root_b64: " << base64_encode(root.data(), root.size()) << "\n";
    std::cout << "leaf_count_padded: " << levels[0].size() << "\n";

    if (!wantChain.empty()) {
        size_t idx = (size_t)-1;
        for (size_t i = 0; i < entries.size(); i++) {
            if (entries[i].name == wantChain) { idx = i; break; }
        }
        if (idx == (size_t)-1) throw std::runtime_error("chainName not found: " + wantChain);

        auto path = merkle_path_for_index(levels, idx);

        std::cout << "\n--- membership proof for chainName=" << wantChain << " (leaf_index=" << idx << ") ---\n";
        std::cout << "pkx_b64: " << base64_encode(entries[idx].pkx.data(), entries[idx].pkx.size()) << "\n";
        std::cout << "pky_b64: " << base64_encode(entries[idx].pky.data(), entries[idx].pky.size()) << "\n";

        std::cout << "path_dirs: [";
        for (size_t i = 0; i < path.dirs.size(); i++) {
            std::cout << path.dirs[i] << (i + 1 == path.dirs.size() ? "" : ",");
        }
        std::cout << "]\n";

        std::cout << "path_siblings_b64:\n";
        for (size_t i = 0; i < path.siblings.size(); i++) {
            std::cout << "  - " << base64_encode(path.siblings[i].data(), path.siblings[i].size()) << "\n";
        }
    }

    return 0;
}