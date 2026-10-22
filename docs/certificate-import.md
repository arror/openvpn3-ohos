# Offline certificate material API

`OvpnImportCertificates(files)` copies input bytes, processes one bounded batch on a Native worker, and resolves with either complete material or a structured error. It does not start or modify a VPN session, select trust, save files, or persist passwords.

Each input has `data: ArrayBuffer`, `password: string`, `passwordProvided: boolean`, and `outputPassword: string`. `passwordProvided` distinguishes a missing password from an explicitly supplied empty password. On `OUTPUT_PASSWORD_REQUIRED`, supply a nonempty output password and retry the batch. PFX private keys are always returned as encrypted PKCS#8; encrypted standalone keys retain protection. Plain standalone keys remain plain unless an output password is provided.

Successful results contain certificate IDs, public-key IDs, subject/issuer names, validity, CA/purpose flags, `selfSigned`, verified `issuerIds`, source file indices, and PEM. Key IDs are SHA-256 public-key IDs, so they can be matched directly to certificates' `publicKeyId`. Multiple PFX identities are enumerated rather than taking the first `PKCS12_parse` match. Private key passwords are not returned; the caller already owns the selected source/output password.

Each deduplicated certificate/key includes `fileIndexes`, containing every distinct zero-based input origin. Repeated material within one input contributes that index only once. The singular `fileIndex` remains the source of the returned PEM representation and, for private keys, the source whose password/output password protects that PEM. A protected representation is preferred over an unprotected duplicate; callers must use `fileIndex` for password selection and `fileIndexes` for provenance display.

Certificates returned as additional PFX material are not necessarily server trust anchors. Applications must confirm CA trust separately from the client presentation chain, omit roots from the client chain where appropriate, and preserve unselected profile fields. `selfSigned` includes signature verification; matching subject/issuer names alone is insufficient.

Common errors include `PASSWORD_REQUIRED`, `OUTPUT_PASSWORD_REQUIRED`, `UNLOCK_FAILED`, `UNSUPPORTED_ENCRYPTION`, `UNSUPPORTED_FORMAT`, `INVALID_CERTIFICATE`, `INVALID_PRIVATE_KEY`, `FILE_LIMIT`, `MATERIAL_LIMIT`, `KDF_LIMIT`, and `IMPORT_BUSY`. `fileIndex` identifies a failed file when applicable. Failed batches have empty certificate/key arrays. A MAC failure cannot reliably distinguish a wrong password from tampering; do not present it as definitively a password error. `unverifiedIntegrity` marks a PFX without MAC protection.

Limits: 8 files, 8 MiB per file, 16 MiB total, 64 certificates, 16 private keys, bounded PEM/SafeBag nesting/counts and issuer signature checks. PBKDF2/PBE iteration limits are 1,000,000 per KDF and 4,000,000 per batch including output encryption. Output uses PBES2/AES-256-CBC with 100,000 PBKDF2 iterations. The application must also check the final profile against OpenVPN Core's profile-size limit.

Supported encrypted inputs use the existing default-provider algorithms: common PBES2/PBKDF2/AES and 3DES PFX. Scrypt-based containers and algorithms outside the declared PBE set return `UNSUPPORTED_ENCRYPTION`. The module does not enable legacy/RC2, load providers, lower TLS security levels, or enable VPN legacy algorithms.

The Host regression generates ephemeral test credentials and covers positive conversion, public-key/issuer relationships, password protection, multi-identity files, corrupted/MAC-less containers and resource limits. A host-only legacy provider is used to generate an RC2 negative fixture; it is never part of the production importer. Run `scripts/test-host.sh`; use `test_certificate_import --fixtures <directory>` only to generate test materials.

## Application-managed private-key protection

`OvpnGeneratePrivateKeyPassword()` generates 32 bytes using OpenSSL `RAND_priv_bytes`, returns a 64-character lowercase hexadecimal password, and throws `KEY_PROTECTION_FAILED` if randomness is unavailable. Temporary native secret buffers are cleansed. Never display, log, export, or put this value in profile/sidecar text.

ArkOvpn supplies a separate generated `outputPassword` for every selected input, including plain private keys and empty-password PFX packages. Source passwords only unlock files. The output password for a deduplicated key is taken from `fileIndex`, and is committed through the application's versioned Asset Store credential transaction. Selection preview is not persistence. Applications must fail closed if encrypted output or its output password is missing. The low-level conversion API retains its existing explicit caller-controlled output policy.
