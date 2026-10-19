// SPDX-License-Identifier: MPL-2.0
// Uses actual compressed bytes from independent compressors; no liblzo link.
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include <openvpn/log/logsimple.hpp>
#undef OPENVPN_LOG
#define OPENVPN_LOG(args) do {} while (0)
#include <openvpn/compress/compress.hpp>
#include "testdata/compression_vectors.hpp"
#if defined(HAVE_LZO)
#error "Regression must exercise the built-in LZO decoder"
#endif
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL line " << __LINE__ << ": " #x << '\n'; std::exit(1); } } while (0)
using namespace openvpn;
struct Stats : SessionStats {
    size_t errors = 0;
    void error(size_t type, const std::string * = nullptr) override {
        CHECK(type == Error::COMPRESS_ERROR); ++errors;
    }
};
std::string unhex(const char *s) {
    std::string out;
    for (; *s; s += 2) out.push_back(static_cast<char>(std::stoul(std::string(s, 2), nullptr, 16)));
    return out;
}
BufferAllocated packet(const Frame::Ptr &frame, const std::string &data) {
    BufferAllocated out; frame->prepare(Frame::DECRYPT_WORK, out); out.write(data.data(), data.size()); return out;
}
std::string wireFor(int mode, const std::string &data) {
    if (mode == 0) return std::string(1, '\x66') + data;
    if (mode == 1) return std::string(1, '\x67') + data.substr(1) + data.substr(0, 1);
    if (mode == 2) return std::string(1, '\x69') + data.substr(1) + data.substr(0, 1);
    return std::string("\x50\x01",2) + data;
}
int main() {
    CompressContext::init_static();
    const auto payload = unhex(compression_vectors::payload);
    const auto lzo = unhex(compression_vectors::lzo), lz4 = unhex(compression_vectors::lz4);
    CHECK(lzo.size() < payload.size()); CHECK(lz4.size() < payload.size());
    const CompressContext::Type types[] = {CompressContext::LZO, CompressContext::LZO_SWAP, CompressContext::LZ4, CompressContext::LZ4v2};
    for (int mode = 0; mode < 4; ++mode) {
        Frame::Ptr frame(new Frame(Frame::Context(512, 1500, 512, 0, 16, 0)));
        auto *rawStats = new Stats; SessionStats::Ptr stats(rawStats);
        CompressContext context(types[mode], true);
        auto decoder = context.new_compressor(frame, stats);
        if (mode < 2) CHECK(std::string(decoder->name()) == "lzo-asym");
        const auto compressed = mode < 2 ? lzo : lz4;
        auto wire = packet(frame, wireFor(mode, compressed));
        decoder->decompress(wire);
        CHECK(rawStats->errors == 0);
        CHECK(wire.size() == payload.size());
        CHECK(std::string(reinterpret_cast<const char *>(wire.c_data()), wire.size()) == payload);
        // Asymmetric mode must continue to send the complete uncompressed bytes.
        auto uplink = packet(frame, payload); decoder->compress(uplink, true);
        CHECK(uplink.size() >= payload.size()); decoder->decompress(uplink);
        CHECK(uplink.size() == payload.size()); CHECK(std::memcmp(uplink.c_data(),payload.data(),payload.size()) == 0);
        // Truncated real compressed data must fail instead of entering the TUN.
        auto invalid = packet(frame, wireFor(mode, compressed.substr(0,4)));
        decoder->decompress(invalid); CHECK(invalid.size() == 0); CHECK(rawStats->errors == 1);
        // A valid compressed stream expanding beyond MTU must fail safely.
        Frame::Ptr small(new Frame(Frame::Context(512, 64, 512, 0, 16, 0)));
        auto bounded = context.new_compressor(small, stats);
        auto overflow = packet(frame, wireFor(mode, compressed));
        bounded->decompress(overflow); CHECK(overflow.size() == 0); CHECK(rawStats->errors == 2);
        std::cout << "PASS real compressed bytes, asymmetric uplink, truncation and overflow: mode=" << mode << '\n';
    }
    std::cout << "Compression regressions passed: 16 checks across LZO/LZO-swap/LZ4/LZ4-v2, no external LZO\n";
}
