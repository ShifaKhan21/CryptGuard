#include "sni_extractor.h"
#include "md5.h"
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace DPI {

// ============================================================================
// TLS SNI Extractor Implementation
// ============================================================================

uint16_t SNIExtractor::readUint16BE(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t SNIExtractor::readUint24BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           data[2];
}

bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t length) {
    // Minimum TLS record: 5 bytes header + 4 bytes handshake header
    if (length < 9) return false;
    
    // Check TLS record header
    // Byte 0: Content Type (should be 0x16 = Handshake)
    if (payload[0] != CONTENT_TYPE_HANDSHAKE) return false;
    
    // Bytes 1-2: TLS Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
    // We accept 0x0300 (SSL 3.0) through 0x0304 (TLS 1.3)
    uint16_t version = readUint16BE(payload + 1);
    if (version < 0x0300 || version > 0x0304) return false;
    
    // Bytes 3-4: Record length
    uint16_t record_length = readUint16BE(payload + 3);
    if (record_length > length - 5) return false;
    
    // Check handshake header (starts at byte 5)
    // Byte 5: Handshake Type (should be 0x01 = Client Hello)
    if (payload[5] != HANDSHAKE_CLIENT_HELLO) return false;
    
    return true;
}

std::optional<std::string> SNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isTLSClientHello(payload, length)) {
        return std::nullopt;
    }
    
    // Skip TLS record header (5 bytes)
    size_t offset = 5;
    
    // Skip handshake header
    // Byte 0: Handshake type (already checked)
    // Bytes 1-3: Length
    uint32_t handshake_length = readUint24BE(payload + offset + 1);
    offset += 4;
    
    // Client Hello body
    // Bytes 0-1: Client version
    offset += 2;
    
    // Bytes 2-33: Random (32 bytes)
    offset += 32;
    
    // Session ID
    if (offset >= length) return std::nullopt;
    uint8_t session_id_length = payload[offset];
    offset += 1 + session_id_length;
    
    // Cipher suites
    if (offset + 2 > length) return std::nullopt;
    uint16_t cipher_suites_length = readUint16BE(payload + offset);
    offset += 2 + cipher_suites_length;
    
    // Compression methods
    if (offset >= length) return std::nullopt;
    uint8_t compression_methods_length = payload[offset];
    offset += 1 + compression_methods_length;
    
    // Extensions
    if (offset + 2 > length) return std::nullopt;
    uint16_t extensions_length = readUint16BE(payload + offset);
    offset += 2;
    
    size_t extensions_end = offset + extensions_length;
    if (extensions_end > length) {
        extensions_end = length;  // Truncated, but try to parse anyway
    }
    
    // Parse extensions to find SNI
    while (offset + 4 <= extensions_end) {
        uint16_t extension_type = readUint16BE(payload + offset);
        uint16_t extension_length = readUint16BE(payload + offset + 2);
        offset += 4;
        
        if (offset + extension_length > extensions_end) break;
        
        if (extension_type == EXTENSION_SNI) {
            // SNI extension found
            // Structure:
            //   SNI List Length (2 bytes)
            //   SNI Type (1 byte) - 0x00 for hostname
            //   SNI Length (2 bytes)
            //   SNI Value (variable)
            
            if (extension_length < 5) break;
            
            uint16_t sni_list_length = readUint16BE(payload + offset);
            if (sni_list_length < 3) break;
            
            uint8_t sni_type = payload[offset + 2];
            uint16_t sni_length = readUint16BE(payload + offset + 3);
            
            if (sni_type != SNI_TYPE_HOSTNAME) break;
            if (sni_length > extension_length - 5) break;
            
            // Extract the hostname
            std::string sni(reinterpret_cast<const char*>(payload + offset + 5), sni_length);
            return sni;
        }
        
        offset += extension_length;
    }
    
    return std::nullopt;
}

std::string SNIExtractor::JA3Data::toString() const {
    std::ostringstream ss;
    ss << version << ",";
    
    for (size_t i = 0; i < ciphers.size(); ++i) {
        ss << ciphers[i] << (i == ciphers.size() - 1 ? "" : "-");
    }
    ss << ",";
    
    for (size_t i = 0; i < extensions.size(); ++i) {
        ss << extensions[i] << (i == extensions.size() - 1 ? "" : "-");
    }
    ss << ",";
    
    for (size_t i = 0; i < elliptic_curves.size(); ++i) {
        ss << elliptic_curves[i] << (i == elliptic_curves.size() - 1 ? "" : "-");
    }
    ss << ",";
    
    for (size_t i = 0; i < elliptic_curve_formats.size(); ++i) {
        ss << static_cast<int>(elliptic_curve_formats[i]) << (i == elliptic_curve_formats.size() - 1 ? "" : "-");
    }
    
    return ss.str();
}

std::optional<std::string> SNIExtractor::extractJA3(const uint8_t* payload, size_t length) {
    if (!isTLSClientHello(payload, length)) return std::nullopt;
    
    JA3Data ja3;
    size_t offset = 5; // Skip Record Header
    
    // Handshake Layer
    // type (1), len (3), version (2)
    ja3.version = readUint16BE(payload + offset + 4);
    offset += 6 + 32; // Skip type, len, version, random
    
    // Session ID
    if (offset >= length) return std::nullopt;
    uint8_t session_id_len = payload[offset];
    offset += 1 + session_id_len;
    
    // Ciphers
    if (offset + 2 > length) return std::nullopt;
    uint16_t ciphers_len = readUint16BE(payload + offset);
    offset += 2;
    for (size_t i = 0; i < ciphers_len; i += 2) {
        if (offset + 2 > length) break;
        ja3.ciphers.push_back(readUint16BE(payload + offset));
        offset += 2;
    }
    
    // Compression
    if (offset >= length) return std::nullopt;
    uint8_t comp_len = payload[offset];
    offset += 1 + comp_len;
    
    // Extensions
    if (offset + 2 > length) return std::nullopt;
    uint16_t ext_total_len = readUint16BE(payload + offset);
    offset += 2;
    
    size_t ext_end = offset + ext_total_len;
    while (offset + 4 <= ext_end && offset + 4 <= length) {
        uint16_t type = readUint16BE(payload + offset);
        uint16_t len = readUint16BE(payload + offset + 2);
        offset += 4;
        
        ja3.extensions.push_back(type);
        
        if (type == 0x000a) { // Supported Groups (Elliptic Curves)
            if (offset + 2 <= length) {
                uint16_t list_len = readUint16BE(payload + offset);
                for (size_t j = 0; j < list_len; j += 2) {
                    if (offset + 2 + j + 2 <= length)
                        ja3.elliptic_curves.push_back(readUint16BE(payload + offset + 2 + j));
                }
            }
        } else if (type == 0x000b) { // EC Point Formats
            if (offset + 1 <= length) {
                uint8_t list_len = payload[offset];
                for (size_t j = 0; j < list_len; ++j) {
                    if (offset + 1 + j < length)
                        ja3.elliptic_curve_formats.push_back(payload[offset + 1 + j]);
                }
            }
        }
        
        offset += len;
    }
    
    std::string ja3_str = ja3.toString();
    return MD5::hash(ja3_str);
}

// ============================================================================
// HTTP Host Header Extractor Implementation
// ============================================================================

bool HTTPHostExtractor::isHTTPRequest(const uint8_t* payload, size_t length) {
    if (length < 4) return false;
    
    // Check for common HTTP methods
    const char* methods[] = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
    
    for (const char* method : methods) {
        if (std::memcmp(payload, method, 4) == 0) {
            return true;
        }
    }
    
    return false;
}

std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isHTTPRequest(payload, length)) {
        return std::nullopt;
    }
    
    // Search for "Host: " header
    const char* host_header = "Host: ";
    const size_t host_header_len = 6;
    
    for (size_t i = 0; i + host_header_len < length; i++) {
        // Check for header (case-insensitive "host:")
        if ((payload[i] == 'H' || payload[i] == 'h') &&
            (payload[i+1] == 'o' || payload[i+1] == 'O') &&
            (payload[i+2] == 's' || payload[i+2] == 'S') &&
            (payload[i+3] == 't' || payload[i+3] == 'T') &&
            payload[i+4] == ':') {
            
            // Skip "Host:" and any whitespace
            size_t start = i + 5;
            while (start < length && (payload[start] == ' ' || payload[start] == '\t')) {
                start++;
            }
            
            // Find end of line
            size_t end = start;
            while (end < length && payload[end] != '\r' && payload[end] != '\n') {
                end++;
            }
            
            if (end > start) {
                std::string host(reinterpret_cast<const char*>(payload + start), end - start);
                
                // Remove port if present
                size_t colon_pos = host.find(':');
                if (colon_pos != std::string::npos) {
                    host = host.substr(0, colon_pos);
                }
                
                return host;
            }
        }
    }
    
    return std::nullopt;
}

// ============================================================================
// DNS Extractor Implementation
// ============================================================================

bool DNSExtractor::isDNSQuery(const uint8_t* payload, size_t length) {
    // Minimum DNS header is 12 bytes
    if (length < 12) return false;
    
    // Check QR bit (byte 2, bit 7) - should be 0 for query
    uint8_t flags = payload[2];
    if (flags & 0x80) return false;  // This is a response, not a query
    
    // Check QDCOUNT (bytes 4-5) - should be > 0
    uint16_t qdcount = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    if (qdcount == 0) return false;
    
    return true;
}

bool DNSExtractor::isDNSResponse(const uint8_t* payload, size_t length) {
    if (length < 12) return false;
    uint8_t flags = payload[2];
    return (flags & 0x80) != 0; // QR bit 1 = Response
}

std::vector<DNSResult> DNSExtractor::extractResults(const uint8_t* payload, size_t length) {
    if (length < 12) return {};
    
    uint16_t qdcount = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    uint16_t ancount = (static_cast<uint16_t>(payload[6]) << 8) | payload[7];
    
    if (ancount == 0) return {};
    
    size_t offset = 12;
    
    // 1. Skip Questions
    for (int i = 0; i < qdcount; ++i) {
        while (offset < length) {
            uint8_t len = payload[offset];
            if (len == 0) { offset++; break; }
            if (len >= 0xC0) { offset += 2; break; } // Pointer
            offset += 1 + len;
        }
        offset += 4; // Type (2) + Class (2)
    }
    
    std::vector<DNSResult> results;
    
    // 2. Parse Answers
    for (int i = 0; i < ancount && offset + 10 <= length; ++i) {
        DNSResult res;
        
        // Name (can be compressed)
        size_t name_offset = offset;
        bool compressed = false;
        while (name_offset < length) {
            uint8_t len = payload[name_offset];
            if (len == 0) { if(!compressed) offset = name_offset + 1; break; }
            if (len >= 0xC0) {
                if(!compressed) offset = name_offset + 2;
                compressed = true;
                break;
            }
            name_offset += 1 + len;
        }
        
        if (offset > length) break;
        
        uint16_t type = (static_cast<uint16_t>(payload[offset]) << 8) | payload[offset+1];
        uint32_t ttl = (static_cast<uint32_t>(payload[offset+2]) << 24) | 
                       (static_cast<uint32_t>(payload[offset+3]) << 16) |
                       (static_cast<uint32_t>(payload[offset+4]) << 8) | 
                       payload[offset+5];
        uint16_t rdlen = (static_cast<uint16_t>(payload[offset+8]) << 8) | payload[offset+9];
        
        res.type = type;
        res.ttl = ttl;
        offset += 10;
        
        if (offset + rdlen > length) break;
        
        // Extract Answer Data
        if (type == 1 && rdlen == 4) { // A Record (IPv4)
            std::ostringstream ss;
            ss << (int)payload[offset] << "." << (int)payload[offset+1] << "."
               << (int)payload[offset+2] << "." << (int)payload[offset+3];
            res.answer = ss.str();
        } else if (type == 5 || type == 2 || type == 12) { // CNAME, NS, PTR (Domain names)
            // For simplicity, we just mark it as a domain answer
            res.answer = "[Domain Name]"; 
        } else if (type == 28 && rdlen == 16) { // AAAA Record (IPv6)
            res.answer = "[IPv6 Address]";
        } else {
            res.answer = "Data size: " + std::to_string(rdlen);
        }
        
        results.push_back(res);
        offset += rdlen;
    }
    
    return results;
}

std::optional<std::string> DNSExtractor::extractQuery(const uint8_t* payload, size_t length) {
    if (length < 12) return std::nullopt;
    
    // DNS query starts at byte 12
    size_t offset = 12;
    std::string domain;
    
    while (offset < length) {
        uint8_t label_length = payload[offset];
        
        if (label_length == 0) {
            // End of domain name
            break;
        }
        
        if (label_length >= 0xC0) {
            // Compression pointer - we don't fully resolve these in the simple extractor
            // But we can skip it
            break;
        }
        
        offset++;
        if (offset + label_length > length) break;
        
        if (!domain.empty()) {
            domain += '.';
        }
        domain += std::string(reinterpret_cast<const char*>(payload + offset), label_length);
        offset += label_length;
    }
    
    return domain.empty() ? std::nullopt : std::optional<std::string>(domain);
}

// ============================================================================
// QUIC SNI Extractor (simplified)
// ============================================================================

bool QUICSNIExtractor::isQUICInitial(const uint8_t* payload, size_t length) {
    if (length < 5) return false;
    
    // QUIC long header starts with 1 bit set (form bit)
    // and the type should be Initial (0x00)
    uint8_t first_byte = payload[0];
    
    // Long header form
    if ((first_byte & 0x80) == 0) return false;
    
    // Check for QUIC version (bytes 1-4)
    // Common versions: 0x00000001 (v1), 0xff000000+ (drafts)
    // We'll be lenient here
    
    return true;
}

std::optional<std::string> QUICSNIExtractor::extract(const uint8_t* payload, size_t length) {
    // QUIC Initial packets contain the TLS Client Hello inside CRYPTO frames
    // This is complex to parse properly due to QUIC framing
    // For now, we'll do a simplified search for the SNI extension pattern
    
    if (!isQUICInitial(payload, length)) {
        return std::nullopt;
    }
    
    // Search for TLS Client Hello pattern within the QUIC packet
    // Look for the handshake type byte followed by SNI extension
    for (size_t i = 0; i + 50 < length; i++) {
        if (payload[i] == 0x01) {  // Client Hello handshake type
            // Try to extract SNI starting from here
            auto result = SNIExtractor::extract(payload + i - 5, length - i + 5);
            if (result) return result;
        }
    }
    
    return std::nullopt;
}

} // namespace DPI
