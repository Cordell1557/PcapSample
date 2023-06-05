#ifndef filterOfflineDevice_h
#define filterOfflineDevice_h

#include <string>
#include <vector>
#include <pcap.h>

struct ContextStruct
{
    pcap_dumper_t* dumpHandle;
    std::vector <const pcap_pkthdr*> vPacketsInFrame;

    u_int unFrameAmount = 0;
    u_int unFrameLimit = 200;

    u_int unStatCountTotal = 0;
    u_int unStatCountPassed = 0;
    u_int unStatCountSkipped = 0;

    u_int unStatMaxRate = 0; // byte/s
};

void got_packet(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet);
int filterOfflineDevice(std::string infile, std::string outfile, u_int rateLimit);

#endif
