#include "pcap_reader.h"
#include <iostream>
#include <cstring>

namespace PacketAnalyzer {

// Magic numbers for PCAP files
constexpr uint32_t PCAP_MAGIC_NATIVE = 0xa1b2c3d4;  // Native byte order (microsec)
constexpr uint32_t PCAP_MAGIC_SWAPPED = 0xd4c3b2a1; // Swapped byte order (microsec)
constexpr uint32_t PCAP_MAGIC_NSEC_NATIVE = 0xa1b23c4d; // Native byte order (nanosec)
constexpr uint32_t PCAP_MAGIC_NSEC_SWAPPED = 0x4d3cb2a1; // Swapped byte order (nanosec)

PcapReader::~PcapReader() {
    close();
}

bool PcapReader::open(const std::string& filename) {
    // Close any previously opened file or live capture
    close();
    
    if (filename == "-") {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_handle_ = pcap_open_offline("-", errbuf);
        if (!pcap_handle_) {
            std::cerr << "Error: Could not open stdin for pcap reading: " << errbuf << std::endl;
            return false;
        }
        
        // Populate global header for downstream classes (like PacketParser)
        global_header_.magic_number = PCAP_MAGIC_NATIVE;
        global_header_.version_major = 2;
        global_header_.version_minor = 4;
        global_header_.snaplen = 65535;
        global_header_.network = pcap_datalink(pcap_handle_);
        needs_byte_swap_ = false;
        
        std::cout << "Opened stdin for pcap streaming." << std::endl;
        return true;
    }
    
    // Open in binary mode - this is crucial for reading raw bytes
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        std::cerr << "Error: Could not open file: " << filename << std::endl;
        return false;
    }
    
    // Read the global header (first 24 bytes of the file)
    file_.read(reinterpret_cast<char*>(&global_header_), sizeof(PcapGlobalHeader));
    if (!file_.good()) {
        std::cerr << "Error: Could not read PCAP global header" << std::endl;
        close();
        return false;
    }
    
    // Check the magic number to determine byte order
    if (global_header_.magic_number == PCAP_MAGIC_NATIVE || 
        global_header_.magic_number == PCAP_MAGIC_NSEC_NATIVE) {
        needs_byte_swap_ = false;
    } else if (global_header_.magic_number == PCAP_MAGIC_SWAPPED ||
               global_header_.magic_number == PCAP_MAGIC_NSEC_SWAPPED) {
        needs_byte_swap_ = true;
        // Swap the header fields we've already read
        global_header_.version_major = maybeSwap16(global_header_.version_major);
        global_header_.version_minor = maybeSwap16(global_header_.version_minor);
        global_header_.snaplen = maybeSwap32(global_header_.snaplen);
        global_header_.network = maybeSwap32(global_header_.network);
    } else {
        std::cerr << "Error: Invalid PCAP magic number: 0x" 
                  << std::hex << global_header_.magic_number << std::dec << std::endl;
        close();
        return false;
    }
    
    std::cout << "Opened PCAP file: " << filename << std::endl;
    return true;
}

bool PcapReader::openLive(const std::string& device_name) {
    if (device_name == "-") {
        return open("-");
    }
    
    close();
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_handle_ = pcap_open_live(device_name.c_str(), 65535, 1, 1000, errbuf);
    if (!pcap_handle_) {
        std::cerr << "Error: Could not open live capture on " << device_name << ": " << errbuf << std::endl;
        return false;
    }
    
    // Fill global header with relevant values for the live capture LinkType
    global_header_.magic_number = PCAP_MAGIC_NATIVE;
    global_header_.version_major = 2;
    global_header_.version_minor = 4;
    global_header_.snaplen = 65535;
    global_header_.network = pcap_datalink(pcap_handle_);
    needs_byte_swap_ = false;
    
    std::cout << "Opened live capture on interface: " << device_name << std::endl;
    return true;
}

void PcapReader::close() {
    if (file_.is_open()) {
        file_.close();
    }
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
    needs_byte_swap_ = false;
}

bool PcapReader::readNextPacket(RawPacket& packet) {
    if (pcap_handle_) {
        struct pcap_pkthdr* header;
        const u_char* data;
        int res = pcap_next_ex(pcap_handle_, &header, &data);
        if (res <= 0) return false;
        
        packet.header.ts_sec = header->ts.tv_sec;
        packet.header.ts_usec = header->ts.tv_usec;
        packet.header.incl_len = header->caplen;
        packet.header.orig_len = header->len;
        
        packet.data.assign(data, data + header->caplen);
        return true;
    }

    if (!file_.is_open()) {
        return false;
    }
    
    // Read the packet header (16 bytes)
    file_.read(reinterpret_cast<char*>(&packet.header), sizeof(PcapPacketHeader));
    if (!file_.good()) {
        // End of file or error
        return false;
    }
    
    // Swap bytes if needed
    if (needs_byte_swap_) {
        packet.header.ts_sec = maybeSwap32(packet.header.ts_sec);
        packet.header.ts_usec = maybeSwap32(packet.header.ts_usec);
        packet.header.incl_len = maybeSwap32(packet.header.incl_len);
        packet.header.orig_len = maybeSwap32(packet.header.orig_len);
    }
    
    // Sanity check on packet length
    if (packet.header.incl_len > global_header_.snaplen || 
        packet.header.incl_len > 65535) {
        std::cerr << "Error: Invalid packet length: " << packet.header.incl_len << std::endl;
        return false;
    }
    
    // Read the packet data
    packet.data.resize(packet.header.incl_len);
    file_.read(reinterpret_cast<char*>(packet.data.data()), packet.header.incl_len);
    if (!file_.good()) {
        std::cerr << "Error: Could not read packet data" << std::endl;
        return false;
    }
    
    return true;
}

uint16_t PcapReader::maybeSwap16(uint16_t value) {
    if (!needs_byte_swap_) return value;
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

uint32_t PcapReader::maybeSwap32(uint32_t value) {
    if (!needs_byte_swap_) return value;
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x000000FF) << 24);
}

} // namespace PacketAnalyzer
