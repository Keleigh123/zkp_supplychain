#include "ecdsa_merkle_verifier.h"
#include "ecdsa_merkle_circuit.h"

#include "arrays/dense.h"
#include "algebra/fp2.h"
#include "algebra/convolution.h"
#include "algebra/reed_solomon.h"
#include "ec/p256.h"
#include "random/transcript.h"
#include "zk/zk_proof.h"
#include "zk/zk_verifier.h"
#include "util/readbuffer.h"

#include <stdexcept>
#include <vector>

namespace zkp {

using Field = proofs::Fp256Base;
using Field2 = proofs::Fp2<Field>;
using FftExtConvolutionFactory = proofs::FFTExtConvolutionFactory<Field, Field2>;
using RSFactory = proofs::ReedSolomonFactory<Field, FftExtConvolutionFactory>;

constexpr size_t kLigeroRate = 2;
constexpr size_t kLigeroNreq = 1;
static constexpr size_t kVersion = 4;

bool verify_ecdsa_merkle_proof(const Proof& proof, const PublicInputs& pub) {
    auto circuit = build_ecdsa_merkle_verify_circuit();
    if (!circuit) {
        throw std::runtime_error("build_ecdsa_merkle_verify_circuit failed");
    }

    const size_t expected_pub_bytes = 32 * circuit->npub_in;
    if (pub.data.size() != expected_pub_bytes) {
        throw std::runtime_error(
            "Bad public input size: got " + std::to_string(pub.data.size()) +
            ", expected " + std::to_string(expected_pub_bytes)
        );
    }

    // Rebuild Dense public inputs exactly as serialized by prover
    proofs::Dense<Field> Pub(1, circuit->npub_in);
    proofs::DenseFiller<Field> pubfill(Pub);

    for (size_t i = 0; i < circuit->npub_in; i++) {
        const uint8_t* p = pub.data.data() + 32 * i;
        auto elt = proofs::p256_base.of_bytes_field(p);
        if (!elt.has_value()) {
            throw std::runtime_error(
                "Invalid public input field element at index " + std::to_string(i)
            );
        }
        pubfill.push_back(elt.value());
    }

    // Same RS / transcript parameters as prover
    Field2 base2(proofs::p256_base);
    Field2::Elt omega{
        proofs::p256_base.of_string("0xf90d338ebd84f5665cfc85c67990e3379fc9563b382a4a4c985a65324b242562"),
        proofs::p256_base.of_string("0xb9e81e42bc97cc4da04fc2e20106e34084738a6474d232c6dbf4174f60a43eac")
    };
    uint64_t root_order = 1ull << 31;

    FftExtConvolutionFactory fft(proofs::p256_base, base2, omega, root_order);
    RSFactory rsf(fft, proofs::p256_base);

    proofs::ZkProof<Field> zkpr(*circuit, kLigeroRate, kLigeroNreq);

    proofs::ReadBuffer rb(proof.data.data(), proof.data.size());
    if (!zkpr.read(rb, proofs::p256_base)) {
        throw std::runtime_error("Failed to deserialize zk proof");
    }

    proofs::Transcript tp(reinterpret_cast<const uint8_t*>("ecdsa_merkle"), 11, kVersion);

    proofs::ZkVerifier<Field, RSFactory> verifier(
    *circuit,
    rsf,
    kLigeroRate,
    kLigeroNreq,
    proofs::p256_base
);
 verifier.recv_commitment(zkpr, tp);
    return verifier.verify(zkpr, Pub, tp);
}

} // namespace zkp