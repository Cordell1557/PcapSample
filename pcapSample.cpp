#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <vector>
#include <string>

#include "pcap.h"
#include "tools.h"

struct ContextStruct
{
    pcap_dumper_t* dumpHandle;
    std::vector <const pcap_pkthdr*> vPacketsInFrame;

    u_int unFrameAmount = 0;
    u_int unFrameLimit = 200;
};


int FilterOfflineDevice(std::string infile, std::string outfile, u_int rateLimit);

int main(int argc, char *argv[])
{
    std::string infile; 
    std::string outfile; 
    u_int rateLimit = 0;

    try
    {
        //////////////////////////////
        infile = "./icmp.pcap";
        outfile = "./out.pcap";
        rateLimit = 100;
        //////////////////////////////

        printf("Start...\n");
        //if(process_command_line(argc, argv, infile, outfile, rateLimit))
        {
            FilterOfflineDevice(infile, outfile, rateLimit);
        }

        printf("Finish.\n");
    }
    catch(std::exception& e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
    }
    catch(...)
    {
        fprintf(stderr, "Unknown error\n");
    }

    //getchar();

    return(0);
}

void got_packet(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet)
{
    timeval frame;
    pcap_pkthdr* pHeader;
    ContextStruct* pContext = (ContextStruct*)arg;

    pHeader = new pcap_pkthdr();
    *pHeader = *header;
    pContext->vPacketsInFrame.push_back(pHeader);

    //printf("tm=%jd/%jd vPacketsInFrame0= %jd/%jd\n", header->ts.tv_sec, header->ts.tv_usec, vPacketsInFrame.at(0)->ts.tv_sec, vPacketsInFrame.at(0)->ts.tv_usec);
    // time frame
    for
    ( 
        timeval_subtract(&(header->ts), &(pContext->vPacketsInFrame.at(0)->ts), &frame);
        frame.tv_sec > 0;
        timeval_subtract(&(header->ts), &(pContext->vPacketsInFrame.at(0)->ts), &frame)
    )
    {
        printf("erase frame= %ld.%ld\n", frame.tv_sec, frame.tv_usec);
        pContext->unFrameAmount -= pContext->vPacketsInFrame.at(0)->len;
        delete pContext->vPacketsInFrame.at(0);
        pContext->vPacketsInFrame.erase(pContext->vPacketsInFrame.begin());
    }
    printf("packet length=%d, tm=%ld.%ld frame= %ld.%ld, %d %ld", header->len, header->ts.tv_sec, header->ts.tv_usec, frame.tv_sec, frame.tv_usec, pContext->unFrameAmount, pContext->vPacketsInFrame.size());
    if((pContext->unFrameAmount + header->len) < pContext->unFrameLimit)
    {
        pContext->unFrameAmount += header->len;
        pcap_dump((u_char*)(pContext->dumpHandle), header, packet);
        printf(" passed %d\n", pContext->unFrameAmount);
    }
    else
    {
        if(pContext->vPacketsInFrame.size() > 0)
        {
            delete pHeader;
            pContext->vPacketsInFrame.pop_back();
        }
        printf(" skipped %d\n", pContext->unFrameAmount + header->len);
    }
}

int FilterOfflineDevice(std::string infile, std::string outfile, u_int rateLimit)
{
    pcap_t *handle;   
    pcap_dumper_t* dumpHandle;
    char errbuf[PCAP_ERRBUF_SIZE]; 
    ContextStruct context;


    // Set up context
    context.unFrameLimit = rateLimit * 125000; // Mbps -> bytes/s 1 Mbps = 1,000,000 bits = 125,000 Bytes 

    // Open offline device
    handle = pcap_open_offline(infile.c_str(), errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", infile.c_str(), errbuf);
        return(2);
    }
    // Open output dump file
    context.dumpHandle = pcap_dump_open(handle, outfile.c_str());
    if(context.dumpHandle == NULL)
    {
        pcap_perror(handle, "pcap_dump_open");
        return(2);
    }

    // loop
    pcap_loop(handle, -1, got_packet, (u_char*)&context);

    // Dump close
    if(context.dumpHandle != NULL)
    {
        pcap_dump_close(context.dumpHandle);
        context.dumpHandle = NULL;
    }

    // Device close
    if(handle != NULL)
    {
        pcap_close(handle);
        handle = NULL;
    }

    return(0);
}    
