// SPDX-License-Identifier: MPL-2.0
#include "../core/certificate_import.hpp"

namespace {
napi_value GeneratePrivateKeyPassword(napi_env env, napi_callback_info) {
    std::string password;
    try {
        password = ovpn_certificate::protectionPassword();
        napi_value result = JsString(env, password);
        ovpn_certificate::wipe(password);
        return result;
    } catch (...) {
        ovpn_certificate::wipe(password);
        napi_throw_error(env, "KEY_PROTECTION_FAILED", "KEY_PROTECTION_FAILED");
        return nullptr;
    }
}
std::atomic<bool> certificateImportBusy{false};
struct CertificateWork {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    std::vector<ovpn_certificate::Input> files;
    ovpn_certificate::Result result;
    std::string error;
    int fileIndex = -1;
};
void CertificateSources(napi_env env, napi_value row, const std::vector<int> &indexes) {
    napi_value sources; napi_create_array_with_length(env, indexes.size(), &sources);
    for (size_t i = 0; i < indexes.size(); ++i) {
        napi_value index; napi_create_int32(env, indexes[i], &index); napi_set_element(env, sources, i, index);
    }
    napi_set_named_property(env, row, "fileIndexes", sources);
}
napi_value CertificateResult(napi_env env, const CertificateWork &work) {
    auto obj = Object(env);
    SetString(env, obj, "errorCode", work.error);
    SetNumber(env, obj, "fileIndex", work.fileIndex);
    SetBool(env, obj, "unverifiedIntegrity", work.result.unverifiedIntegrity);
    napi_value certs, keys;
    napi_create_array_with_length(env, work.result.certificates.size(), &certs);
    for (size_t i = 0; i < work.result.certificates.size(); ++i) {
        const auto &cert = work.result.certificates[i]; auto row = Object(env);
        SetString(env, row, "id", cert.id); SetString(env, row, "name", cert.name);
        SetString(env, row, "issuer", cert.issuer); SetString(env, row, "publicKeyId", cert.publicKeyId);
        SetString(env, row, "validFrom", cert.validFrom); SetString(env, row, "validTo", cert.validTo);
        SetString(env, row, "algorithm", cert.algorithm); SetString(env, row, "pem", cert.pem);
        SetBool(env, row, "ca", cert.ca); SetBool(env, row, "expired", cert.expired);
        SetBool(env, row, "clientUsage", cert.clientUsage); SetNumber(env, row, "fileIndex", cert.fileIndex);
        SetBool(env, row, "selfSigned", cert.selfSigned); CertificateSources(env, row, cert.fileIndexes);
        napi_value issuers; napi_create_array_with_length(env, cert.issuerIds.size(), &issuers);
        for (size_t j = 0; j < cert.issuerIds.size(); ++j) napi_set_element(env, issuers, j, JsString(env, cert.issuerIds[j]));
        napi_set_named_property(env, row, "issuerIds", issuers); napi_set_element(env, certs, i, row);
    }
    napi_create_array_with_length(env, work.result.keys.size(), &keys);
    for (size_t i = 0; i < work.result.keys.size(); ++i) {
        const auto &key = work.result.keys[i]; auto row = Object(env);
        SetString(env, row, "id", key.id); SetString(env, row, "algorithm", key.algorithm); SetString(env, row, "pem", key.pem);
        SetBool(env, row, "encrypted", key.encrypted); SetNumber(env, row, "fileIndex", key.fileIndex); CertificateSources(env, row, key.fileIndexes);
        napi_set_element(env, keys, i, row);
    }
    napi_set_named_property(env, obj, "certificates", certs); napi_set_named_property(env, obj, "keys", keys); return obj;
}
void ExecuteCertificateImport(napi_env, void *data) {
    auto *work = static_cast<CertificateWork *>(data);
    try { work->result = ovpn_certificate::inspect(work->files); }
    catch (const ovpn_certificate::Failure &error) { work->error = error.code; work->fileIndex = error.fileIndex; }
    catch (...) { work->error = "CONVERSION_FAILED"; }
    if (!work->error.empty()) work->result = {}; // Never expose partially decoded material after a failed batch.
    work->files.clear();
}
void CompleteCertificateImport(napi_env env, napi_status status, void *data) {
    std::unique_ptr<CertificateWork> work(static_cast<CertificateWork *>(data));
    certificateImportBusy = false;
    if (status != napi_ok) { work->error = "IMPORT_CANCELLED"; work->result = {}; }
    napi_resolve_deferred(env, work->deferred, CertificateResult(env, *work));
    napi_delete_async_work(env, work->work);
}
napi_value ImportCertificates(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1] = {nullptr}; napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    auto work = std::make_unique<CertificateWork>(); napi_value promise;
    napi_create_promise(env, &work->deferred, &promise);
    bool array = false; uint32_t count = 0;
    if (argc == 1) napi_is_array(env, args[0], &array);
    if (array) napi_get_array_length(env, args[0], &count);
    if (!array || count == 0 || count > ovpn_certificate::MAX_FILES) work->error = "FILE_LIMIT";
    size_t total = 0;
    try {
        if (count <= ovpn_certificate::MAX_FILES) work->files.reserve(count);
        for (uint32_t i = 0; i < count && work->error.empty(); ++i) {
            napi_value row = nullptr, buffer = nullptr, provided = nullptr;
            if (napi_get_element(env, args[0], i, &row) != napi_ok || napi_get_named_property(env, row, "data", &buffer) != napi_ok) {
                work->error = "INVALID_FORMAT"; work->fileIndex = i; break;
            }
            void *bytes = nullptr; size_t size = 0;
            if (napi_get_arraybuffer_info(env, buffer, &bytes, &size) != napi_ok || size == 0 ||
                size > ovpn_certificate::MAX_FILE_BYTES || total + size > ovpn_certificate::MAX_BATCH_BYTES) {
                work->error = size == 0 ? "EMPTY_FILE" : "FILE_LIMIT"; work->fileIndex = i; break;
            }
            total += size; work->files.emplace_back(); auto &file = work->files.back();
            file.bytes.assign(static_cast<unsigned char *>(bytes), static_cast<unsigned char *>(bytes) + size);
            // Cap strings before copying; never silently truncate passwords.
            for (const char *name : {"password", "outputPassword"}) {
                napi_value value; size_t length = 0;
                if (napi_get_named_property(env, row, name, &value) == napi_ok &&
                    napi_get_value_string_utf8(env, value, nullptr, 0, &length) == napi_ok && length > 1024) {
                    work->error = "PASSWORD_INVALID"; work->fileIndex = i;
                }
            }
            if (!work->error.empty()) break;
            file.password = Field(env, row, "password"); file.outputPassword = Field(env, row, "outputPassword");
            if (napi_get_named_property(env, row, "passwordProvided", &provided) == napi_ok)
                napi_get_value_bool(env, provided, &file.passwordProvided);
        }
    } catch (...) { work->error = "CONVERSION_FAILED"; }
    bool expected = false;
    if (work->error.empty() && !certificateImportBusy.compare_exchange_strong(expected, true)) work->error = "IMPORT_BUSY";
    if (!work->error.empty()) { napi_resolve_deferred(env, work->deferred, CertificateResult(env, *work)); return promise; }
    napi_value name = JsString(env, "CertificateImport");
    if (napi_create_async_work(env, nullptr, name, ExecuteCertificateImport, CompleteCertificateImport, work.get(), &work->work) != napi_ok ||
        napi_queue_async_work(env, work->work) != napi_ok) {
        certificateImportBusy = false;
        if (work->work) napi_delete_async_work(env, work->work);
        work->error = "CONVERSION_FAILED"; napi_resolve_deferred(env, work->deferred, CertificateResult(env, *work)); return promise;
    }
    work.release(); return promise;
}
} // namespace
