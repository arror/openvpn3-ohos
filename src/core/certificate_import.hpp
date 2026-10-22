// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <openssl/asn1.h>
#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

// Offline conversion only. Never loads providers or changes the VPN crypto context.
namespace ovpn_certificate {
constexpr size_t MAX_FILE_BYTES = 8 * 1024 * 1024;
constexpr size_t MAX_BATCH_BYTES = 16 * 1024 * 1024;
constexpr size_t MAX_FILES = 8, MAX_CERTS = 64, MAX_KEYS = 16;
constexpr int64_t MAX_KDF_ITERATIONS = 1000000;

struct Failure : std::runtime_error {
    std::string code;
    int fileIndex = -1;
    explicit Failure(const std::string &value) : std::runtime_error(value), code(value) {}
};
inline void require(bool ok, const char *code) { if (!ok) throw Failure(code); }
inline void wipe(std::string &value) {
    if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
    value.clear();
}
inline std::string protectionPassword(int (*randomBytes)(unsigned char *, int) = RAND_priv_bytes) {
    struct Secret { unsigned char bytes[32]{}; ~Secret() { OPENSSL_cleanse(bytes, sizeof(bytes)); } } secret;
    require(randomBytes(secret.bytes, sizeof(secret.bytes)) == 1, "KEY_PROTECTION_FAILED");
    static constexpr char hex[] = "0123456789abcdef";
    std::string password; password.reserve(64);
    for (unsigned char byte : secret.bytes) { password += hex[byte >> 4]; password += hex[byte & 15]; }
    return password;
}
struct Input {
    std::vector<unsigned char> bytes;
    std::string password, outputPassword;
    bool passwordProvided = false;
    ~Input() { if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size()); wipe(password); wipe(outputPassword); }
};
template<class T, void (*Free)(T *)> using Ptr = std::unique_ptr<T, decltype(Free)>;
using CertPtr = Ptr<X509, X509_free>;
using KeyPtr = Ptr<EVP_PKEY, EVP_PKEY_free>;
struct BioFree { void operator()(BIO *p) const { BIO_free(p); } };
using BioPtr = std::unique_ptr<BIO, BioFree>;
struct Cert {
    std::string id, name, issuer, validFrom, validTo, algorithm, publicKeyId, pem;
    bool ca = false, expired = false, clientUsage = true, selfSigned = false;
    std::vector<std::string> issuerIds;
    int fileIndex = 0;
    std::vector<int> fileIndexes;
};
struct Key {
    std::string id, algorithm, pem;
    bool encrypted = false;
    int fileIndex = 0;
    std::vector<int> fileIndexes;
    ~Key() { wipe(pem); }
};
struct Result { std::vector<Cert> certificates; std::vector<Key> keys; bool unverifiedIntegrity = false; };
inline BioPtr memoryBio() { return BioPtr(BIO_new(BIO_s_mem())); }
inline std::string bioText(BIO *bio) {
    char *data = nullptr; const long size = BIO_get_mem_data(bio, &data);
    require(size >= 0, "CONVERSION_FAILED");
    return std::string(data, static_cast<size_t>(size));
}
inline std::string digest(const unsigned char *data, size_t size) {
    unsigned char hash[EVP_MAX_MD_SIZE]; unsigned int length = 0;
    require(EVP_Digest(data, size, hash, &length, EVP_sha256(), nullptr) == 1, "CONVERSION_FAILED");
    static constexpr char hex[] = "0123456789abcdef";
    std::string out; out.reserve(length * 2);
    for (unsigned i = 0; i < length; ++i) { out += hex[hash[i] >> 4]; out += hex[hash[i] & 15]; }
    return out;
}
inline std::string publicId(EVP_PKEY *key) {
    unsigned char *data = nullptr; const int size = i2d_PUBKEY(key, &data);
    require(size > 0, "UNSUPPORTED_KEY");
    const std::string out = digest(data, size); OPENSSL_free(data); return out;
}
inline std::string algorithm(EVP_PKEY *key) {
    require(EVP_PKEY_is_a(key, "RSA") || EVP_PKEY_is_a(key, "RSA-PSS") || EVP_PKEY_is_a(key, "EC") ||
            EVP_PKEY_is_a(key, "ED25519") || EVP_PKEY_is_a(key, "ED448"), "UNSUPPORTED_KEY");
    require(EVP_PKEY_get_bits(key) > 0 && EVP_PKEY_get_bits(key) <= 8192, "UNSUPPORTED_KEY");
    const char *type = EVP_PKEY_get0_type_name(key);
    return std::string(type ? type : "") + " " + std::to_string(EVP_PKEY_get_bits(key));
}
inline std::string nameText(X509_NAME *name) {
    auto bio = memoryBio(); require(bio != nullptr, "CONVERSION_FAILED");
    require(X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253) >= 0, "INVALID_CERTIFICATE");
    return bioText(bio.get());
}
inline std::string timeText(const ASN1_TIME *time) {
    auto bio = memoryBio(); require(bio != nullptr && ASN1_TIME_print(bio.get(), time) == 1, "INVALID_CERTIFICATE");
    return bioText(bio.get());
}
inline int64_t checkIterations(const ASN1_INTEGER *iteration) {
    if (!iteration) return 1; // PKCS#12 omitted iteration means 1.
    int64_t value = 0;
    require(ASN1_INTEGER_get_int64(&value, iteration) == 1 && value > 0 && value <= MAX_KDF_ITERATIONS, "KDF_LIMIT");
    return value;
}
inline int64_t checkPbe(const X509_ALGOR *algorithm) {
    require(algorithm != nullptr, "INVALID_FORMAT");
    const ASN1_OBJECT *object = nullptr; const void *parameter = nullptr; int type = 0;
    X509_ALGOR_get0(&object, &type, &parameter, algorithm);
    require(type == V_ASN1_SEQUENCE && parameter != nullptr, "UNSUPPORTED_ENCRYPTION");
    const auto *sequence = static_cast<const ASN1_STRING *>(parameter);
    const unsigned char *cursor = ASN1_STRING_get0_data(sequence);
    const unsigned char *end = cursor + ASN1_STRING_length(sequence);
    const int nid = OBJ_obj2nid(object);
    if (nid == NID_pbes2) {
        Ptr<PBE2PARAM, PBE2PARAM_free> parameters(d2i_PBE2PARAM(nullptr, &cursor, end - cursor), PBE2PARAM_free);
        require(parameters != nullptr && cursor == end, "INVALID_FORMAT");
        const ASN1_OBJECT *kdf = nullptr; const void *kdfParameter = nullptr; int kdfType = 0;
        X509_ALGOR_get0(&kdf, &kdfType, &kdfParameter, parameters->keyfunc);
        require(OBJ_obj2nid(kdf) == NID_id_pbkdf2 && kdfType == V_ASN1_SEQUENCE && kdfParameter, "UNSUPPORTED_ENCRYPTION");
        const auto *encoded = static_cast<const ASN1_STRING *>(kdfParameter);
        const unsigned char *p = ASN1_STRING_get0_data(encoded);
        Ptr<PBKDF2PARAM, PBKDF2PARAM_free> pbkdf(d2i_PBKDF2PARAM(nullptr, &p, ASN1_STRING_length(encoded)), PBKDF2PARAM_free);
        require(pbkdf != nullptr, "INVALID_FORMAT"); const int64_t iterations = checkIterations(pbkdf->iter);
        const ASN1_OBJECT *cipher = nullptr; X509_ALGOR_get0(&cipher, nullptr, nullptr, parameters->encryption);
        const int cipherNid = OBJ_obj2nid(cipher);
        require(cipherNid == NID_aes_128_cbc || cipherNid == NID_aes_192_cbc || cipherNid == NID_aes_256_cbc ||
                cipherNid == NID_des_ede3_cbc, "UNSUPPORTED_ENCRYPTION");
        return iterations;
    } else {
        // Existing default-provider 3DES PFX works; RC2/RC4 and legacy-provider algorithms are not added.
        require(nid == NID_pbe_WithSHA1And3_Key_TripleDES_CBC || nid == NID_pbe_WithSHA1And2_Key_TripleDES_CBC, "UNSUPPORTED_ENCRYPTION");
        Ptr<PBEPARAM, PBEPARAM_free> parameters(d2i_PBEPARAM(nullptr, &cursor, end - cursor), PBEPARAM_free);
        require(parameters != nullptr && cursor == end, "INVALID_FORMAT"); return checkIterations(parameters->iter);
    }
}
inline int64_t checkEncryptedKey(const X509_SIG *key) {
    const X509_ALGOR *algorithm = nullptr; X509_SIG_get0(key, &algorithm, nullptr); return checkPbe(algorithm);
}

class Reader {
    Result result;
    std::vector<CertPtr> certificates;
    size_t bagsSeen = 0, kdfWork = 0, parsedObjects = 0;
    void budget(size_t iterations = 1) {
        // Cap the whole batch too, not just each individual encrypted object.
        kdfWork += iterations; require(kdfWork <= 4000000, "KDF_LIMIT");
    }
    void addCert(X509 *raw, int file) {
        CertPtr cert(raw, X509_free); require(cert != nullptr, "INVALID_CERTIFICATE"); ++parsedObjects;
        unsigned char *der = nullptr; const int length = i2d_X509(cert.get(), &der);
        require(length > 0, "INVALID_CERTIFICATE"); const std::string id = digest(der, length); OPENSSL_free(der);
        const auto existing = std::find_if(result.certificates.begin(), result.certificates.end(), [&](const Cert &c) { return c.id == id; });
        if (existing != result.certificates.end()) {
            if (std::find(existing->fileIndexes.begin(), existing->fileIndexes.end(), file) == existing->fileIndexes.end()) existing->fileIndexes.push_back(file);
            return;
        }
        require(result.certificates.size() < MAX_CERTS, "MATERIAL_LIMIT");
        KeyPtr key(X509_get_pubkey(cert.get()), EVP_PKEY_free); require(key != nullptr, "INVALID_CERTIFICATE");
        Cert out; out.id = id; out.fileIndex = file; out.fileIndexes = {file}; out.name = nameText(X509_get_subject_name(cert.get()));
        out.issuer = nameText(X509_get_issuer_name(cert.get())); out.publicKeyId = publicId(key.get()); out.algorithm = algorithm(key.get());
        out.ca = X509_check_ca(cert.get()) > 0;
        out.selfSigned = X509_check_issued(cert.get(), cert.get()) == X509_V_OK && X509_verify(cert.get(), key.get()) == 1;
        ERR_clear_error();
        out.validFrom = timeText(X509_get0_notBefore(cert.get())); out.validTo = timeText(X509_get0_notAfter(cert.get()));
        const int before = X509_cmp_current_time(X509_get0_notBefore(cert.get()));
        const int after = X509_cmp_current_time(X509_get0_notAfter(cert.get()));
        require(before != 0 && after != 0, "INVALID_CERTIFICATE"); out.expired = before > 0 || after < 0;
        out.clientUsage = X509_check_purpose(cert.get(), X509_PURPOSE_SSL_CLIENT, 0) == 1;
        auto pem = memoryBio(); require(pem && PEM_write_bio_X509(pem.get(), cert.get()) == 1, "CONVERSION_FAILED");
        out.pem = bioText(pem.get()); result.certificates.push_back(std::move(out)); certificates.push_back(std::move(cert));
    }
    void addKey(EVP_PKEY *raw, const Input &input, int file, bool encrypted, bool bundle) {
        KeyPtr key(raw, EVP_PKEY_free); require(key != nullptr, "INVALID_PRIVATE_KEY"); ++parsedObjects;
        const std::string keyAlgorithm = algorithm(key.get());
        const std::string id = publicId(key.get());
        const auto existing = std::find_if(result.keys.begin(), result.keys.end(), [&](const Key &k) { return k.id == id; });
        std::vector<int> sources = existing == result.keys.end() ? std::vector<int>{} : existing->fileIndexes;
        if (std::find(sources.begin(), sources.end(), file) == sources.end()) sources.push_back(file);
        // Preserve all provenance while still preferring a protected representation and its own password source.
        if (existing != result.keys.end() && (existing->encrypted || (!encrypted && !bundle && input.outputPassword.empty()))) {
            existing->fileIndexes = std::move(sources); return;
        }
        require(result.keys.size() < MAX_KEYS || existing != result.keys.end(), "MATERIAL_LIMIT");
        Ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_free> context(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr), EVP_PKEY_CTX_free);
        require(context && EVP_PKEY_private_check(context.get()) == 1, "INVALID_PRIVATE_KEY");
        Key out; out.id = id; out.fileIndex = file; out.fileIndexes = std::move(sources); out.algorithm = keyAlgorithm;
        const std::string &password = input.outputPassword.empty() ? input.password : input.outputPassword;
        out.encrypted = encrypted || bundle || !password.empty();
        if (out.encrypted) require(!password.empty(), "OUTPUT_PASSWORD_REQUIRED");
        auto pem = memoryBio(); require(pem != nullptr, "CONVERSION_FAILED");
        if (out.encrypted) {
            budget(100000);
            Ptr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free> info(EVP_PKEY2PKCS8(key.get()), PKCS8_PRIV_KEY_INFO_free);
            require(info != nullptr, "CONVERSION_FAILED");
            Ptr<X509_SIG, X509_SIG_free> protectedKey(PKCS8_encrypt(-1, EVP_aes_256_cbc(), password.data(), password.size(),
                nullptr, 0, 100000, info.get()), X509_SIG_free);
            require(protectedKey && PEM_write_bio_PKCS8(pem.get(), protectedKey.get()) == 1, "CONVERSION_FAILED");
        } else require(PEM_write_bio_PKCS8PrivateKey(pem.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1, "CONVERSION_FAILED");
        out.pem = bioText(pem.get());
        if (existing != result.keys.end()) *existing = out; else result.keys.push_back(std::move(out));
    }
    void readKey(const unsigned char *data, size_t size, const Input &input, int file, bool encrypted, const char *type) {
        if (encrypted) { budget(); require(input.passwordProvided, "PASSWORD_REQUIRED"); }
        EVP_PKEY *key = nullptr;
        Ptr<OSSL_DECODER_CTX, OSSL_DECODER_CTX_free> decoder(OSSL_DECODER_CTX_new_for_pkey(&key, type, nullptr, nullptr,
                EVP_PKEY_PRIVATE_KEY, nullptr, nullptr), OSSL_DECODER_CTX_free);
        require(decoder != nullptr, "UNSUPPORTED_KEY");
        OSSL_DECODER_CTX_set_passphrase(decoder.get(), reinterpret_cast<const unsigned char *>(input.password.data()), input.password.size());
        const unsigned char *cursor = data; size_t remaining = size;
        const bool ok = OSSL_DECODER_from_data(decoder.get(), &cursor, &remaining) == 1;
        if (!ok || remaining != 0) { EVP_PKEY_free(key); throw Failure(encrypted ? "UNLOCK_FAILED" : "INVALID_PRIVATE_KEY"); }
        addKey(key, input, file, encrypted, false);
    }
    void readP7(PKCS7 *p7, int file) {
        STACK_OF(X509) *certs = nullptr;
        if (PKCS7_type_is_signed(p7)) certs = p7->d.sign->cert;
        else if (PKCS7_type_is_signedAndEnveloped(p7)) throw Failure("UNSUPPORTED_FORMAT");
        else throw Failure("UNSUPPORTED_FORMAT");
        require(certs && sk_X509_num(certs) > 0, "NO_CERTIFICATES");
        for (int i = 0; i < sk_X509_num(certs); ++i) {
            X509 *cert = sk_X509_value(certs, i); require(X509_up_ref(cert) == 1, "CONVERSION_FAILED"); addCert(cert, file);
        }
    }
    void readBags(const STACK_OF(PKCS12_SAFEBAG) *bags, const Input &input, int file, unsigned depth) {
        require(bags && depth <= 8, "MATERIAL_LIMIT");
        for (int i = 0; i < sk_PKCS12_SAFEBAG_num(bags); ++i) {
            require(++bagsSeen <= 256, "MATERIAL_LIMIT");
            const auto *bag = sk_PKCS12_SAFEBAG_value(bags, i);
            const int nid = PKCS12_SAFEBAG_get_nid(bag);
            if (nid == NID_certBag) {
                require(PKCS12_SAFEBAG_get_bag_nid(bag) == NID_x509Certificate, "UNSUPPORTED_FORMAT");
                addCert(PKCS12_SAFEBAG_get1_cert(bag), file);
            } else if (nid == NID_keyBag || nid == NID_pkcs8ShroudedKeyBag) {
                Ptr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free> decrypted(nullptr, PKCS8_PRIV_KEY_INFO_free);
                const PKCS8_PRIV_KEY_INFO *info = nullptr;
                if (nid == NID_pkcs8ShroudedKeyBag) {
                    const int64_t iterations = checkEncryptedKey(PKCS12_SAFEBAG_get0_pkcs8(bag)); budget(iterations);
                    decrypted.reset(PKCS12_decrypt_skey(bag, input.password.c_str(), input.password.size()));
                    if (!decrypted && input.password.empty()) { budget(iterations); decrypted.reset(PKCS12_decrypt_skey(bag, nullptr, 0)); }
                    require(decrypted != nullptr, input.passwordProvided ? "UNLOCK_FAILED" : "PASSWORD_REQUIRED"); info = decrypted.get();
                } else info = PKCS12_SAFEBAG_get0_p8inf(bag);
                require(info != nullptr, "INVALID_PRIVATE_KEY");
                addKey(EVP_PKCS82PKEY(info), input, file, nid == NID_pkcs8ShroudedKeyBag, true);
            } else if (nid == NID_safeContentsBag) readBags(PKCS12_SAFEBAG_get0_safes(bag), input, file, depth + 1);
            else throw Failure("UNSUPPORTED_FORMAT");
        }
    }
    void readP12(PKCS12 *p12, const Input &input, int file) {
        const bool hasMac = PKCS12_mac_present(p12) == 1;
        if (hasMac) {
            const ASN1_INTEGER *iteration = nullptr; const X509_ALGOR *macAlgorithm = nullptr;
            PKCS12_get0_mac(nullptr, &macAlgorithm, nullptr, &iteration, p12);
            const ASN1_OBJECT *macObject = nullptr; X509_ALGOR_get0(&macObject, nullptr, nullptr, macAlgorithm);
            const int macNid = OBJ_obj2nid(macObject);
            require(macNid == NID_sha1 || macNid == NID_sha256 || macNid == NID_sha384 || macNid == NID_sha512, "UNSUPPORTED_ENCRYPTION");
            budget(checkIterations(iteration));
            bool verified = PKCS12_verify_mac(p12, input.password.c_str(), input.password.size()) == 1;
            if (!verified && input.password.empty()) verified = PKCS12_verify_mac(p12, nullptr, 0) == 1;
            require(verified, input.passwordProvided ? "UNLOCK_FAILED" : "PASSWORD_REQUIRED");
        } else result.unverifiedIntegrity = true;
        struct P7StackFree { void operator()(STACK_OF(PKCS7) *p) const { sk_PKCS7_pop_free(p, PKCS7_free); } };
        std::unique_ptr<STACK_OF(PKCS7), P7StackFree> safes(PKCS12_unpack_authsafes(p12));
        require(safes && sk_PKCS7_num(safes.get()) <= 64, "INVALID_FORMAT");
        for (int i = 0; i < sk_PKCS7_num(safes.get()); ++i) {
            PKCS7 *p7 = sk_PKCS7_value(safes.get(), i);
            struct BagsFree { void operator()(STACK_OF(PKCS12_SAFEBAG) *p) const { sk_PKCS12_SAFEBAG_pop_free(p, PKCS12_SAFEBAG_free); } };
            std::unique_ptr<STACK_OF(PKCS12_SAFEBAG), BagsFree> bags;
            if (PKCS7_type_is_data(p7)) bags.reset(PKCS12_unpack_p7data(p7));
            else if (PKCS7_type_is_encrypted(p7)) {
                const int64_t iterations = checkPbe(p7->d.encrypted->enc_data->algorithm); budget(iterations);
                bags.reset(PKCS12_unpack_p7encdata(p7, input.password.c_str(), input.password.size()));
                if (!bags && input.password.empty()) { budget(iterations); bags.reset(PKCS12_unpack_p7encdata(p7, nullptr, 0)); }
                require(bags != nullptr, input.passwordProvided ? "UNLOCK_FAILED" : "PASSWORD_REQUIRED");
            } else throw Failure("UNSUPPORTED_FORMAT");
            require(bags != nullptr, "INVALID_FORMAT"); readBags(bags.get(), input, file, 0);
        }
    }
    void readDer(const unsigned char *data, size_t size, const Input &input, int file) {
        const unsigned char *cursor = data;
        CertPtr cert(d2i_X509(nullptr, &cursor, size), X509_free);
        if (cert && cursor == data + size) { addCert(cert.release(), file); return; }
        ERR_clear_error(); cursor = data;
        Ptr<PKCS12, PKCS12_free> p12(d2i_PKCS12(nullptr, &cursor, size), PKCS12_free);
        if (p12 && cursor == data + size) { readP12(p12.get(), input, file); return; }
        ERR_clear_error(); cursor = data;
        Ptr<PKCS7, PKCS7_free> p7(d2i_PKCS7(nullptr, &cursor, size), PKCS7_free);
        if (p7 && cursor == data + size) { readP7(p7.get(), file); return; }
        ERR_clear_error(); cursor = data;
        Ptr<X509_SIG, X509_SIG_free> encrypted(d2i_X509_SIG(nullptr, &cursor, size), X509_SIG_free);
        const bool isEncrypted = encrypted && cursor == data + size;
        if (isEncrypted) budget(checkEncryptedKey(encrypted.get()));
        ERR_clear_error(); readKey(data, size, input, file, isEncrypted, "DER");
    }
    void readPem(const Input &input, int file) {
        const std::string text(input.bytes.begin(), input.bytes.end()); size_t position = 0, count = 0;
        while ((position = text.find("-----BEGIN ", position)) != std::string::npos) {
            require(++count <= 128, "MATERIAL_LIMIT");
            const size_t labelEnd = text.find("-----", position + 11);
            require(labelEnd != std::string::npos, "INVALID_FORMAT");
            const std::string label = text.substr(position + 11, labelEnd - position - 11);
            const std::string endMarker = "-----END " + label + "-----";
            const size_t end = text.find(endMarker, labelEnd + 5); require(end != std::string::npos, "INVALID_FORMAT");
            const std::string block = text.substr(position, end + endMarker.size() - position) + "\n";
            BioPtr bio(BIO_new_mem_buf(block.data(), block.size())); require(bio != nullptr, "CONVERSION_FAILED");
            if (label == "CERTIFICATE" || label == "TRUSTED CERTIFICATE" || label == "X509 CERTIFICATE")
                addCert(PEM_read_bio_X509_AUX(bio.get(), nullptr, nullptr, nullptr), file);
            else if (label == "PKCS7") {
                Ptr<PKCS7, PKCS7_free> p7(PEM_read_bio_PKCS7(bio.get(), nullptr, nullptr, nullptr), PKCS7_free);
                require(p7 != nullptr, "INVALID_FORMAT"); readP7(p7.get(), file);
            } else if (label == "PRIVATE KEY" || label == "RSA PRIVATE KEY" || label == "EC PRIVATE KEY" || label == "ENCRYPTED PRIVATE KEY") {
                bool encrypted = label == "ENCRYPTED PRIVATE KEY" || block.find("Proc-Type: 4,ENCRYPTED") != std::string::npos;
                if (label == "ENCRYPTED PRIVATE KEY") {
                    Ptr<X509_SIG, X509_SIG_free> info(PEM_read_bio_PKCS8(bio.get(), nullptr, nullptr, nullptr), X509_SIG_free);
                    require(info != nullptr, "INVALID_FORMAT"); budget(checkEncryptedKey(info.get()));
                }
                // Traditional encrypted PEM must also stay within the supported default-provider algorithms.
                const auto dek = block.find("DEK-Info:");
                if (dek != std::string::npos) {
                    const auto eol = block.find('\n', dek); const auto cipher = block.substr(dek, eol - dek);
                    require(cipher.find("AES-128-CBC,") != std::string::npos || cipher.find("AES-192-CBC,") != std::string::npos ||
                            cipher.find("AES-256-CBC,") != std::string::npos || cipher.find("DES-EDE3-CBC,") != std::string::npos,
                            "UNSUPPORTED_ENCRYPTION");
                }
                readKey(reinterpret_cast<const unsigned char *>(block.data()), block.size(), input, file, encrypted, "PEM");
            } else if (label != "EC PARAMETERS") throw Failure("UNSUPPORTED_FORMAT");
            position = end + endMarker.size();
        }
        require(count > 0, "UNSUPPORTED_FORMAT");
    }
public:
    Result read(const std::vector<Input> &inputs) {
        require(!inputs.empty() && inputs.size() <= MAX_FILES, "FILE_LIMIT"); size_t total = 0;
        for (size_t i = 0; i < inputs.size(); ++i) {
            try {
                const auto &input = inputs[i]; total += input.bytes.size();
                require(!input.bytes.empty(), "EMPTY_FILE");
                require(input.bytes.size() <= MAX_FILE_BYTES && total <= MAX_BATCH_BYTES, "FILE_LIMIT");
                require(input.password.size() <= 1024 && input.outputPassword.size() <= 1024 &&
                        input.password.find('\0') == std::string::npos && input.outputPassword.find('\0') == std::string::npos, "PASSWORD_INVALID");
                ERR_clear_error();
                const size_t oldObjects = parsedObjects;
                const std::string marker = "-----BEGIN ";
                if (std::search(input.bytes.begin(), input.bytes.end(), marker.begin(), marker.end()) != input.bytes.end()) readPem(input, i);
                else readDer(input.bytes.data(), input.bytes.size(), input, i);
                // Duplicates can legitimately add no new objects; a file containing only EC parameters cannot.
                require(parsedObjects > oldObjects, "NO_MATERIAL");
            } catch (Failure &error) { error.fileIndex = static_cast<int>(i); ERR_clear_error(); throw; }
        }
        size_t signatures = 0;
        for (size_t i = 0; i < certificates.size(); ++i) {
            for (size_t j = 0; j < certificates.size(); ++j) {
                if (i == j || !result.certificates[j].ca) continue;
                if (X509_check_issued(certificates[j].get(), certificates[i].get()) != X509_V_OK) continue;
                require(++signatures <= 256, "MATERIAL_LIMIT");
                KeyPtr key(X509_get_pubkey(certificates[j].get()), EVP_PKEY_free);
                if (key && X509_verify(certificates[i].get(), key.get()) == 1) result.certificates[i].issuerIds.push_back(result.certificates[j].id);
                ERR_clear_error();
            }
        }
        require(!result.certificates.empty() || !result.keys.empty(), "NO_MATERIAL"); return result;
    }
};
inline Result inspect(const std::vector<Input> &inputs) { return Reader().read(inputs); }
} // namespace ovpn_certificate
