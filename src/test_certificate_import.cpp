// SPDX-License-Identifier: MPL-2.0
#include "core/certificate_import.hpp"
#include <openssl/provider.h>
#include <functional>
#include <iostream>
#include <filesystem>
#include <fstream>

using namespace ovpn_certificate;
static int checks = 0;
static void check(bool value, const char *label) { ++checks; if (!value) throw std::runtime_error(label); }
static KeyPtr makeKey(bool ec = false) {
    return KeyPtr(ec ? EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1") :
                  EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", 2048), EVP_PKEY_free);
}
static CertPtr makeCert(EVP_PKEY *key, const std::string &name, bool ca, X509 *issuer, EVP_PKEY *signer, bool expired = false) {
    CertPtr cert(X509_new(), X509_free); check(cert != nullptr, "X509_new");
    static int serial = 1; X509_set_version(cert.get(), 2); ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial++);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), expired ? -1800 : 86400 * 30);
    X509_set_pubkey(cert.get(), key);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(cert.get()), "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char *>(name.data()), name.size(), -1, 0);
    X509_set_issuer_name(cert.get(), issuer ? X509_get_subject_name(issuer) : X509_get_subject_name(cert.get()));
    X509V3_CTX context; X509V3_set_ctx(&context, issuer ? issuer : cert.get(), cert.get(), nullptr, nullptr, 0);
    for (auto extension : std::vector<std::pair<int, std::string>>{
        {NID_basic_constraints, ca ? "critical,CA:TRUE" : "critical,CA:FALSE"},
        {NID_key_usage, ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature,keyEncipherment"},
        {NID_ext_key_usage, ca ? "clientAuth,serverAuth" : "clientAuth"}}) {
        Ptr<X509_EXTENSION, X509_EXTENSION_free> ext(X509V3_EXT_conf_nid(nullptr, &context, extension.first,
            const_cast<char *>(extension.second.c_str())), X509_EXTENSION_free);
        check(ext && X509_add_ext(cert.get(), ext.get(), -1) == 1, "extension");
    }
    check(X509_sign(cert.get(), signer ? signer : key, EVP_sha256()) > 0, "sign"); return cert;
}
static std::string certPem(X509 *cert) { auto bio = memoryBio(); PEM_write_bio_X509(bio.get(), cert); return bioText(bio.get()); }
static std::string keyPem(EVP_PKEY *key, const std::string &password = "", bool traditional = false) {
    auto bio = memoryBio(); const EVP_CIPHER *cipher = password.empty() ? nullptr : EVP_aes_256_cbc();
    const char *pass = password.empty() ? nullptr : password.data();
    check((traditional ? PEM_write_bio_PrivateKey_traditional(bio.get(), key, cipher, reinterpret_cast<const unsigned char *>(pass), password.size(), nullptr, nullptr) :
        PEM_write_bio_PKCS8PrivateKey(bio.get(), key, cipher, pass, password.size(), nullptr, nullptr)) == 1, "key encode");
    return bioText(bio.get());
}
static Input input(const std::string &data, const std::string &password = "", bool provided = false, const std::string &output = "") {
    Input in; in.bytes.assign(data.begin(), data.end()); in.password = password; in.passwordProvided = provided;
    in.outputPassword = output; return in;
}
template<class T> static std::string der(T *object, int (*encode)(const T *, unsigned char **)) {
    unsigned char *data = nullptr; const int size = encode(object, &data); check(size > 0, "DER encode");
    std::string out(reinterpret_cast<char *>(data), size); OPENSSL_free(data); return out;
}
static void fails(const std::vector<Input> &files, const std::string &code, int index = 0) {
    try { inspect(files); throw std::runtime_error("expected " + code); }
    catch (const Failure &error) { check(error.code == code, ("wrong error: " + error.code + " expected " + code).c_str());
        check(error.fileIndex == index, "error file index"); }
}
static std::string pfx(EVP_PKEY *key, X509 *cert, X509 *ca, const std::string &password, int pbe = NID_aes_256_cbc, int iter = 1000) {
    STACK_OF(X509) *chain = sk_X509_new_null(); if (ca) sk_X509_push(chain, ca);
    Ptr<PKCS12, PKCS12_free> package(PKCS12_create(password.c_str(), "test identity", key, cert, chain, pbe, pbe, iter, iter, 0), PKCS12_free);
    sk_X509_free(chain); check(package != nullptr, "PFX encode"); return der<PKCS12>(package.get(), i2d_PKCS12);
}
int main(int argc, char **argv) {
    try {
        auto caKey = makeKey(); auto ca = makeCert(caKey.get(), "root", true, nullptr, nullptr);
        auto interKey = makeKey(); auto inter = makeCert(interKey.get(), "intermediate", true, ca.get(), caKey.get());
        auto key = makeKey(); auto client = makeCert(key.get(), "client", false, inter.get(), interKey.get());
        auto ecKey = makeKey(true); auto ecCert = makeCert(ecKey.get(), "ec client", false, ca.get(), caKey.get());
        if (argc == 3 && std::string(argv[1]) == "--fixtures") {
            const std::filesystem::path directory(argv[2]); std::filesystem::create_directories(directory);
            const auto write = [&](const std::string &name, const std::string &data) {
                std::ofstream file(directory / name, std::ios::binary); file.write(data.data(), data.size()); check(file.good(), "fixture write");
            };
            auto alternateKey = makeKey(); auto alternateRoot = makeCert(alternateKey.get(), "alternate root", true, nullptr, nullptr);
            auto cross = makeCert(interKey.get(), "intermediate", true, alternateRoot.get(), alternateKey.get());
            auto lowerKey = makeKey(); auto lower = makeCert(lowerKey.get(), "lower intermediate", true, inter.get(), interKey.get());
            auto deep = makeCert(key.get(), "deep client", false, lower.get(), lowerKey.get());
            for (const auto &pair : std::vector<std::pair<X509 *, EVP_PKEY *>>{{ca.get(), caKey.get()}, {inter.get(), caKey.get()}, {client.get(), interKey.get()}, {ecCert.get(), caKey.get()},
                {alternateRoot.get(), alternateKey.get()}, {cross.get(), alternateKey.get()}, {lower.get(), interKey.get()}, {deep.get(), lowerKey.get()}}) {
                ASN1_TIME_set_string_X509(X509_getm_notBefore(pair.first), "20200101000000Z");
                ASN1_TIME_set_string_X509(X509_getm_notAfter(pair.first), "20400101000000Z");
                check(X509_sign(pair.first, pair.second, EVP_sha256()) > 0, "fixture long validity");
            }
            write("ca.der", der<X509>(ca.get(), i2d_X509)); write("client.der", der<X509>(client.get(), i2d_X509));
            write("client.key", keyPem(key.get())); write("intermediate.pem", certPem(inter.get()));
            write("encrypted.key", keyPem(key.get(), "fixture-secret"));
            write("modern.pfx", pfx(key.get(), client.get(), inter.get(), "fixture-secret"));
            write("empty.pfx", pfx(key.get(), client.get(), nullptr, ""));
            write("different.key", keyPem(ecKey.get()));
            write("different.der", der<X509>(ecCert.get(), i2d_X509));
            write("alternate-ca.der", der<X509>(alternateRoot.get(), i2d_X509)); write("cross-intermediate.pem", certPem(cross.get()));
            write("lower-intermediate.pem", certPem(lower.get())); write("deep-client.der", der<X509>(deep.get(), i2d_X509));
            std::cout << "Generated test-only certificate fixtures\n"; return 0;
        }
        const auto batch = inspect({input(certPem(ca.get())), input(der<X509>(client.get(), i2d_X509)), input(keyPem(key.get())), input(certPem(inter.get()))});
        check(batch.certificates.size() == 3 && batch.keys.size() == 1, "batch classification");
        check(batch.certificates[0].ca && !batch.certificates[1].ca, "CA classification");
        check(batch.certificates[1].publicKeyId == batch.keys[0].id, "certificate/key cryptographic match");
        check(batch.certificates[1].issuerIds == std::vector<std::string>{batch.certificates[2].id}, "issuer signature chain");
        check(batch.certificates[2].issuerIds == std::vector<std::string>{batch.certificates[0].id}, "root signature chain");
        check(batch.keys[0].pem.find("BEGIN PRIVATE KEY") != std::string::npos, "normalized PKCS8");
        check(batch.certificates[0].selfSigned && !batch.certificates[2].selfSigned, "self-signed requires signature verification");
        for (bool traditional : {false, true}) for (const std::string &password : {std::string(), std::string("密钥密码  ")}) {
            for (EVP_PKEY *material : {key.get(), ecKey.get()}) {
                const auto read = inspect({input(keyPem(material, password, traditional), password, !password.empty())});
                check(read.keys.size() == 1 && read.keys[0].id == publicId(material), "RSA/EC PEM variants");
                check(read.keys[0].encrypted == !password.empty(), "preserve protection");
                const auto roundtrip = inspect({input(read.keys[0].pem, password, true)});
                check(roundtrip.keys[0].id == read.keys[0].id, "encrypted output roundtrip");
            }
        }
        for (EVP_PKEY *material : {key.get(), ecKey.get()}) {
            auto read = inspect({input(der<EVP_PKEY>(material, i2d_PrivateKey))});
            check(read.keys[0].id == publicId(material), "PKCS1/SEC1 DER");
            Ptr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free> info(EVP_PKEY2PKCS8(material), PKCS8_PRIV_KEY_INFO_free);
            read = inspect({input(der<PKCS8_PRIV_KEY_INFO>(info.get(), i2d_PKCS8_PRIV_KEY_INFO))});
            check(read.keys[0].id == publicId(material), "PKCS8 DER");
            Ptr<X509_SIG, X509_SIG_free> encrypted(PKCS8_encrypt(-1, EVP_aes_256_cbc(), "secret", 6, nullptr, 0, 1000, info.get()), X509_SIG_free);
            read = inspect({input(der<X509_SIG>(encrypted.get(), i2d_X509_SIG), "secret", true)});
            check(read.keys[0].encrypted, "encrypted PKCS8 DER");
        }
        auto mixed = inspect({input(certPem(ca.get()) + certPem(client.get()) + keyPem(key.get()) + certPem(ca.get()))});
        check(mixed.certificates.size() == 2 && mixed.keys.size() == 1, "mixed PEM and duplicate certificates");
        auto origins = inspect({input(certPem(ca.get()) + certPem(ca.get())), input(certPem(ca.get())), input(certPem(ca.get()))});
        check(origins.certificates.size() == 1 && origins.certificates[0].fileIndexes == std::vector<int>({0, 1, 2}), "deduplicated certificate retains all distinct file origins");
        auto duplicates = inspect({input(keyPem(key.get())), input(keyPem(key.get(), "secret"), "secret", true)});
        check(duplicates.keys.size() == 1 && duplicates.keys[0].encrypted && duplicates.keys[0].fileIndex == 1, "prefer protected duplicate key");
        check(duplicates.keys[0].fileIndexes == std::vector<int>({0, 1}), "protected duplicate keeps both origins");
        auto reverseDuplicates = inspect({input(keyPem(key.get(), "secret"), "secret", true), input(keyPem(key.get()))});
        check(reverseDuplicates.keys.size() == 1 && reverseDuplicates.keys[0].fileIndex == 0 && reverseDuplicates.keys[0].fileIndexes == std::vector<int>({0, 1}), "encrypted winner retains later unencrypted origin");
        auto repeatedKey = inspect({input(keyPem(key.get()) + keyPem(key.get())), input(keyPem(key.get()))});
        check(repeatedKey.keys.size() == 1 && repeatedKey.keys[0].fileIndexes == std::vector<int>({0, 1}), "same-file repeated key origin appears only once");
        auto protectedOutput = inspect({input(keyPem(key.get())), input(keyPem(key.get()), "", false, "new-output")});
        check(protectedOutput.keys.size() == 1 && protectedOutput.keys[0].encrypted && protectedOutput.keys[0].fileIndex == 1 && protectedOutput.keys[0].fileIndexes == std::vector<int>({0, 1}), "explicit output protection wins over prior plain representation");
        auto mismatch = inspect({input(certPem(client.get())), input(keyPem(ecKey.get()))});
        check(mismatch.certificates[0].publicKeyId != mismatch.keys[0].id, "mismatched key stays identifiable");

        // Both P7B encodings, independent of extension.
        Ptr<PKCS7, PKCS7_free> p7(PKCS7_new(), PKCS7_free); PKCS7_set_type(p7.get(), NID_pkcs7_signed);
        PKCS7_content_new(p7.get(), NID_pkcs7_data); PKCS7_add_certificate(p7.get(), ca.get()); PKCS7_add_certificate(p7.get(), client.get());
        auto pem7 = memoryBio(); PEM_write_bio_PKCS7(pem7.get(), p7.get());
        for (auto data : {der<PKCS7>(p7.get(), i2d_PKCS7), bioText(pem7.get())})
            check(inspect({input(data)}).certificates.size() == 2, "PKCS7 PEM/DER");

        const auto modern = pfx(key.get(), client.get(), ca.get(), "密码 pfx");
        fails({input(modern)}, "PASSWORD_REQUIRED");
        fails({input(modern, "wrong", true)}, "UNLOCK_FAILED");
        auto read = inspect({input(modern, "密码 pfx", true)});
        check(read.certificates.size() == 2 && read.keys.size() == 1 && read.keys[0].encrypted, "modern PFX extraction");
        check(inspect({input(read.keys[0].pem, "密码 pfx", true)}).keys[0].id == publicId(key.get()), "PFX protection roundtrip");
        const auto empty = pfx(key.get(), client.get(), nullptr, "");
        fails({input(empty)}, "OUTPUT_PASSWORD_REQUIRED");
        check(inspect({input(empty, "", false, "new key password")}).keys[0].encrypted, "empty-password PFX protected output");
        check(inspect({input(pfx(key.get(), client.get(), nullptr, "existing", NID_pbe_WithSHA1And3_Key_TripleDES_CBC), "existing", true)}).keys.size() == 1,
              "existing default-provider PFX remains supported");

        // Multiple SafeBags must not silently collapse to PKCS12_parse's first identity.
        STACK_OF(PKCS12_SAFEBAG) *bags = nullptr;
        check(PKCS12_add_key(&bags, key.get(), 0, 1000, NID_aes_256_cbc, "multi") != nullptr, "first identity");
        check(PKCS12_add_key(&bags, ecKey.get(), 0, 1000, NID_aes_256_cbc, "multi") != nullptr, "second identity");
        PKCS12_add_cert(&bags, client.get()); PKCS12_add_cert(&bags, ecCert.get());
        STACK_OF(PKCS7) *safes = nullptr; check(PKCS12_add_safe(&safes, bags, -1, 0, nullptr) == 1, "safe");
        Ptr<PKCS12, PKCS12_free> multi(PKCS12_add_safes(safes, NID_pkcs7_data), PKCS12_free);
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free); sk_PKCS7_pop_free(safes, PKCS7_free);
        read = inspect({input(der<PKCS12>(multi.get(), i2d_PKCS12), "multi", true)});
        check(read.unverifiedIntegrity, "missing MAC is reported, not claimed verified");
        check(multi && PKCS12_set_mac(multi.get(), "multi", 5, nullptr, 0, 1000, nullptr) == 1, "multi MAC");
        read = inspect({input(der<PKCS12>(multi.get(), i2d_PKCS12), "multi", true)});
        check(read.keys.size() == 2 && read.certificates.size() == 2, "all PFX identities enumerated");
        Ptr<PKCS12, PKCS12_free> nullPassword(PKCS12_create(nullptr, "null password", key.get(), client.get(), nullptr,
            NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, 1000, 1000, 0), PKCS12_free);
        check(nullPassword != nullptr, "null-password fixture");
        check(inspect({input(der<PKCS12>(nullPassword.get(), i2d_PKCS12), "", false, "new password")}).keys[0].encrypted, "NULL and empty PFX passwords");
        const ASN1_OCTET_STRING *mac = nullptr; PKCS12_get0_mac(&mac, nullptr, nullptr, nullptr, multi.get());
        const std::string macBytes(reinterpret_cast<const char *>(ASN1_STRING_get0_data(mac)), ASN1_STRING_length(mac));
        auto tampered = der<PKCS12>(multi.get(), i2d_PKCS12); const auto macOffset = tampered.find(macBytes);
        check(macOffset != std::string::npos, "MAC fixture location"); tampered[macOffset] ^= 1;
        fails({input(tampered, "multi", true)}, "UNLOCK_FAILED");

        // Legacy is used ONLY by this host fixture writer, never by the importer.
        OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(nullptr, "legacy"); check(legacy != nullptr, "fixture legacy provider");
        const auto old = pfx(key.get(), client.get(), nullptr, "old", NID_pbe_WithSHA1And40BitRC2_CBC);
        OSSL_PROVIDER_unload(legacy);
        fails({input(old, "old", true)}, "UNSUPPORTED_ENCRYPTION");
        auto expired = makeCert(key.get(), "expired", false, ca.get(), caKey.get(), true);
        check(inspect({input(certPem(expired.get()))}).certificates[0].expired, "expired warning");
        auto badIssuer = makeCert(key.get(), "forged issuer", false, ca.get(), ecKey.get());
        check(inspect({input(certPem(badIssuer.get()) + certPem(ca.get()))}).certificates[0].issuerIds.empty(), "signature checked, not just names");
        fails({input(keyPem(key.get(), "secret"))}, "PASSWORD_REQUIRED");
        fails({input(keyPem(key.get(), "secret"), "bad", true)}, "UNLOCK_FAILED");
        auto publicOnly = memoryBio(); PEM_write_bio_PUBKEY(publicOnly.get(), key.get());
        fails({input(bioText(publicOnly.get()))}, "UNSUPPORTED_FORMAT");
        std::string tooManyCertificates;
        for (unsigned i = 0; i <= MAX_CERTS; ++i) tooManyCertificates += certPem(makeCert(ecKey.get(), "limit-" + std::to_string(i), false, ca.get(), caKey.get()).get());
        fails({input(tooManyCertificates)}, "MATERIAL_LIMIT");
        fails({input(certPem(ca.get())), input("not a certificate")}, "INVALID_PRIVATE_KEY", 1);
        fails({input("-----BEGIN CERTIFICATE-----\ntruncated")}, "INVALID_FORMAT");
        fails({input(der<X509>(ca.get(), i2d_X509) + "trailing data")}, "INVALID_PRIVATE_KEY");
        fails({input("")}, "EMPTY_FILE");
        fails({input(std::string(MAX_FILE_BYTES + 1, 'x'))}, "FILE_LIMIT");
        fails(std::vector<Input>(MAX_FILES + 1), "FILE_LIMIT", -1);
        fails({input(keyPem(key.get()), std::string("nul\0password", 12), true)}, "PASSWORD_INVALID");
        fails({input(pfx(key.get(), client.get(), nullptr, "budget", NID_aes_256_cbc, MAX_KDF_ITERATIONS + 1), "budget", true)}, "KDF_LIMIT");
        const std::string managedPassword = protectionPassword(), secondPassword = protectionPassword();
        check(managedPassword.size() == 64 && managedPassword != secondPassword, "independent 256-bit output passwords");
        check(managedPassword.find_first_not_of("0123456789abcdef") == std::string::npos, "password encoding");
        try { protectionPassword([](unsigned char *, int) { return 0; }); throw std::runtime_error("RNG failure accepted"); }
        catch (const Failure &error) { check(error.code == "KEY_PROTECTION_FAILED", "RNG fails closed"); }
        for (const auto &source : std::vector<Input>{ input(keyPem(key.get()), "", false, managedPassword),
                input(keyPem(key.get(), "source-secret"), "source-secret", true, managedPassword),
                input(pfx(key.get(), client.get(), inter.get(), "source-secret"), "source-secret", true, managedPassword),
                input(pfx(key.get(), client.get(), inter.get(), ""), "", false, managedPassword) }) {
            const auto secured = inspect({source});
            check(secured.keys.size() == 1 && secured.keys[0].encrypted, "all input types produce protected private keys");
            check(secured.keys[0].pem.find("BEGIN ENCRYPTED PRIVATE KEY") != std::string::npos, "encrypted PKCS8 output");
            const auto restored = inspect({input(secured.keys[0].pem, managedPassword, true)});
            check(restored.keys[0].id == publicId(key.get()), "managed password unlocks the same private identity");
            fails({input(secured.keys[0].pem, "source-secret", true)}, "UNLOCK_FAILED");
            fails({input(secured.keys[0].pem, "", true)}, "UNLOCK_FAILED");
        }
        std::cout << "Certificate import: " << checks << " checks passed\n";
    } catch (const std::exception &error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
}
