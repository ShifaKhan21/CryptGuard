// CryptGuard DPI Engine - Self-contained, single-file implementation
// Compiles with: g++ -std=c++17 -pthread -o dpi_engine.exe engine_main.cpp
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <stdexcept>

// ============================================================================
// PCAP structures (cross-platform)
// ============================================================================
#pragma pack(push, 1)
struct PcapFileHeader {
    uint32_t magic;
    uint16_t major, minor;
    int32_t  zone;
    uint32_t sigfigs, snaplen, linktype;
};
struct PcapRecordHeader {
    uint32_t ts_sec, ts_usec, incl_len, orig_len;
};
#pragma pack(pop)

// ============================================================================
// Byte-order helpers (portable)
// ============================================================================
static inline uint16_t b16(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static inline uint32_t b32(const uint8_t* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static std::string ipStr(uint32_t ip) {
    char buf[20];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (ip>>24)&0xFF,(ip>>16)&0xFF,(ip>>8)&0xFF,ip&0xFF);
    return buf;
}
// ============================================================================
// SNI Extractor (TLS Client Hello)
// ============================================================================
static std::string extractSNI(const uint8_t* data, size_t len) {
    if (len < 5) return "";
    // TLS record: type=22 (handshake), version=0x03xx
    if (data[0] != 0x16) return "";
    if (data[1] != 0x03 && data[1] != 0x02) return "";
    if (len < 9) return "";
    // Handshake type = 1 (Client Hello)
    if (data[5] != 0x01) return "";
    size_t off = 5 + 4; // skip handshake header
    if (off + 2 > len) return "";
    off += 2; // version
    if (off + 32 > len) return "";
    off += 32; // random
    if (off + 1 > len) return "";
    uint8_t sid_len = data[off++];
    off += sid_len;
    if (off + 2 > len) return "";
    uint16_t cs_len = b16(data + off); off += 2;
    off += cs_len;
    if (off + 1 > len) return "";
    uint8_t comp_len = data[off++];
    off += comp_len;
    // Extensions
    if (off + 2 > len) return "";
    uint16_t ext_total = b16(data + off); off += 2;
    size_t ext_end = off + ext_total;
    while (off + 4 <= ext_end && off + 4 <= len) {
        uint16_t etype = b16(data + off); off += 2;
        uint16_t elen  = b16(data + off); off += 2;
        if (etype == 0x0000 && off + elen <= len) { // SNI extension
            if (elen < 5) { off += elen; continue; }
            size_t p = off + 2; // skip list length
            if (p + 3 > off + elen) { off += elen; continue; }
            p++; // name_type
            uint16_t name_len = b16(data + p); p += 2;
            if (p + name_len > off + elen || p + name_len > len) { off += elen; continue; }
            return std::string((const char*)(data + p), name_len);
        }
        off += elen;
    }
    return "";
}

// ============================================================================
// App name from SNI
// ============================================================================
static std::string sniToApp(const std::string& sni) {
    auto has = [&](const char* s){ return sni.find(s) != std::string::npos; };
    if (has("google") || has("goog") || has("youtube"))  return "Google";
    if (has("facebook") || has("fb.com"))                return "Facebook";
    if (has("twitter") || has("twimg"))                  return "Twitter";
    if (has("instagram"))                                return "Instagram";
    if (has("netflix"))                                  return "Netflix";
    if (has("amazon") || has("aws"))                     return "Amazon";
    if (has("microsoft") || has("azure"))                return "Microsoft";
    if (has("apple") || has("icloud") || has("iTunes")) return "Apple";
    if (has("whatsapp"))                                 return "WhatsApp";
    if (has("telegram"))                                 return "Telegram";
    if (has("tiktok"))                                   return "TikTok";
    if (has("spotify"))                                  return "Spotify";
    if (has("zoom.us") || has("zoom.com"))               return "Zoom";
    if (has("discord"))                                  return "Discord";
    if (has("github"))                                   return "GitHub";
    if (has("cloudflare"))                               return "Cloudflare";
    return "HTTPS";
}

// ============================================================================
// JSON escaping
// ============================================================================
static std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else out += c;
    }
    return out;
}

// ============================================================================
// Main processing
// ============================================================================
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: dpi_engine <input.pcap> <output.pcap> [--json <report.json>] [--block-app <app>]\n";
        return 1;
    }
    std::string input_file  = argv[1];
    std::string output_file = argv[2];
    std::string json_file;
    std::vector<std::string> blocked_apps;

    for (int i = 3; i < argc; i++) {
        if (std::string(argv[i]) == "--json" && i+1 < argc)
            json_file = argv[++i];
        else if (std::string(argv[i]) == "--block-app" && i+1 < argc)
            blocked_apps.push_back(argv[++i]);
    }

    // Open input PCAP
    std::ifstream in(input_file, std::ios::binary);
    if (!in) {
        std::cerr << "Cannot open input: " << input_file << "\n";
        return 1;
    }

    PcapFileHeader fh;
    in.read(reinterpret_cast<char*>(&fh), sizeof(fh));
    if (!in || (fh.magic != 0xa1b2c3d4 && fh.magic != 0xd4c3b2a1)) {
        std::cerr << "Not a valid PCAP file\n";
        return 1;
    }
    bool swap = (fh.magic == 0xd4c3b2a1);

    auto rd32 = [&](uint32_t v){ return swap ? __builtin_bswap32(v) : v; };
    auto rd16 = [&](uint16_t v){ return swap ? (uint16_t)__builtin_bswap16(v) : v; };

    // Open output PCAP
    std::ofstream out(output_file, std::ios::binary);
    if (!out) {
        std::cerr << "Cannot open output: " << output_file << "\n";
        return 1;
    }
    out.write(reinterpret_cast<const char*>(&fh), sizeof(fh));

    // Stats
    uint64_t total_packets = 0, total_bytes = 0;
    uint64_t forwarded = 0, dropped = 0;
    uint64_t tcp_count = 0, udp_count = 0;
    std::unordered_map<std::string, uint64_t> app_counts;
    std::vector<std::pair<std::string, std::string>> sni_records; // sni, app

    // Process packets
    while (in) {
        PcapRecordHeader rh;
        in.read(reinterpret_cast<char*>(&rh), sizeof(rh));
        if (!in) break;

        uint32_t plen = rd32(rh.incl_len);
        if (plen > 65535) break;

        std::vector<uint8_t> pkt(plen);
        in.read(reinterpret_cast<char*>(pkt.data()), plen);
        if (!in) break;

        total_packets++;
        total_bytes += plen;

        bool block = false;
        std::string detected_sni;
        std::string detected_app;

        if (plen < 14) goto forward_pkt;
        {
            // Ethernet -> IPv4
            uint16_t etype = (uint16_t)((pkt[12] << 8) | pkt[13]);
            if (etype != 0x0800) goto forward_pkt; // not IPv4

            if (plen < 34) goto forward_pkt;
            uint8_t ihl = (pkt[14] & 0x0F) * 4;
            uint8_t proto = pkt[14 + 9]; // IP protocol
            if (proto == 6) tcp_count++;
            else if (proto == 17) udp_count++;

            size_t transport_off = 14 + ihl;
            if (transport_off + 4 >= plen) goto forward_pkt;

            uint16_t dst_port = (uint16_t)((pkt[transport_off+2] << 8) | pkt[transport_off+3]);

            // TLS inspection on port 443
            if (proto == 6 && dst_port == 443) {
                uint8_t tcp_data_off = (pkt[transport_off + 12] >> 4) * 4;
                size_t payload_off = transport_off + tcp_data_off;
                if (payload_off < plen) {
                    size_t payload_len = plen - payload_off;
                    std::string sni = extractSNI(pkt.data() + payload_off, payload_len);
                    if (!sni.empty()) {
                        detected_sni = sni;
                        detected_app = sniToApp(sni);
                        app_counts[detected_app]++;
                        sni_records.push_back({detected_sni, detected_app});
                    }
                }
            } else if (proto == 6 && dst_port == 80) {
                app_counts["HTTP"]++;
                detected_app = "HTTP";
            } else if (proto == 17 && dst_port == 53) {
                app_counts["DNS"]++;
                detected_app = "DNS";
            } else if (detected_app.empty()) {
                app_counts["Other"]++;
            }

            // Check if blocked
            for (const auto& ba : blocked_apps) {
                if (detected_app == ba) { block = true; break; }
            }
        }

        forward_pkt:
        if (block) {
            dropped++;
        } else {
            forwarded++;
            out.write(reinterpret_cast<const char*>(&rh), sizeof(rh));
            out.write(reinterpret_cast<const char*>(pkt.data()), pkt.size());
        }
    }

    in.close();
    out.close();

    // CLI report
    std::cout << "\n=== DPI Engine Report ===\n";
    std::cout << "Total Packets : " << total_packets << "\n";
    std::cout << "Total Bytes   : " << total_bytes << "\n";
    std::cout << "Forwarded     : " << forwarded << "\n";
    std::cout << "Dropped       : " << dropped << "\n";
    std::cout << "TCP           : " << tcp_count << "\n";
    std::cout << "UDP           : " << udp_count << "\n";
    std::cout << "=========================\n";

    // JSON report
    if (!json_file.empty()) {
        std::ofstream jf(json_file);
        if (jf) {
            jf << "{\n";
            jf << "  \"total_packets\": " << total_packets << ",\n";
            jf << "  \"total_bytes\": "   << total_bytes   << ",\n";
            jf << "  \"forwarded\": "     << forwarded     << ",\n";
            jf << "  \"dropped\": "       << dropped       << ",\n";
            jf << "  \"tcp_packets\": "   << tcp_count     << ",\n";
            jf << "  \"udp_packets\": "   << udp_count     << ",\n";
            jf << "  \"applications\": [\n";
            bool first = true;
            for (const auto& [app, cnt] : app_counts) {
                if (!first) jf << ",\n";
                jf << "    { \"name\": \"" << jsonEscape(app) << "\", \"count\": " << cnt << " }";
                first = false;
            }
            jf << "\n  ],\n";
            jf << "  \"snis\": [\n";
            first = true;
            // Deduplicate
            std::unordered_map<std::string, std::string> seen_sni;
            for (const auto& [sni, app] : sni_records) seen_sni[sni] = app;
            for (const auto& [sni, app] : seen_sni) {
                if (!first) jf << ",\n";
                jf << "    { \"domain\": \"" << jsonEscape(sni) << "\", \"app\": \"" << jsonEscape(app) << "\" }";
                first = false;
            }
            jf << "\n  ]\n";
            jf << "}\n";
            std::cout << "JSON report saved: " << json_file << "\n";
        }
    }

    return 0;
}
