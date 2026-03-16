#include <pcap.h>
#include <iostream>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("-", errbuf);

    if (handle == nullptr) {
        std::cerr << "Error opening stdin: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Successfully opened stdin for pcap reading." << std::endl;
    
    struct pcap_pkthdr *header;
    const u_char *data;
    int res;
    int count = 0;

    while ((res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue; // Timeout
        count++;
        if (count % 10 == 0) std::cout << "Received " << count << " packets..." << std::endl;
        if (count >= 50) break;
    }

    pcap_close(handle);
    return 0;
}
