#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <vector>
#include <string>
#include <stdexcept>

#include <pcap.h>

#include "filterOfflineDevice.h"
#include "tools.h"

int filterOfflineDevice(std::string infile, std::string outfile, u_int rateLimit)
{
    pcap_t *handle;   
    pcap_dumper_t* dumpHandle;
    char errbuf[PCAP_ERRBUF_SIZE]; 
    ContextStruct context;
    int nRet = 0;

    try
    {
        // Set up context
        context.unFrameLimit = rateLimit * 125000; // Mbps -> bytes/s 1 Mbps = 1,000,000 bits = 125,000 Bytes 

        // Open offline device
        printf("\nOpening %s... ", infile.c_str());
        handle = pcap_open_offline(infile.c_str(), errbuf);
        if (handle == NULL) 
        {
            throw std::runtime_error(std::string("Opening Failed: ") + errbuf);
        }
        printf("done\n");
        
        // Open output dump file
        printf("Creating %s... ", outfile.c_str());
        context.dumpHandle = pcap_dump_open(handle, outfile.c_str());
        if(context.dumpHandle == NULL)
        {
            throw std::runtime_error(std::string("Creating failed: ") + pcap_geterr(handle));
        }
        printf("done\n");

        // loop
        printf("Processing...\n");
        pcap_loop(handle, -1, got_packet, (u_char*)&context);
        printf("\ndone\n");

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

        // Statics output
        printf("\n");
        printf("\033[1;33m%d\033[0m\tpackets in\t%s\n", context.unStatCountTotal, infile.c_str());
        printf("\033[1;32m%d\033[0m\tpackets in %s\n", context.unStatCountPassed, outfile.c_str());
        printf("\033[1;31m%d\033[0m\tpackets skipped with \033[1;33m%.2f\033[0m Mbps max rate\n", context.unStatCountSkipped, (context.unStatMaxRate/125000.0));
    }
    catch(std::exception& e)
    {
        printf("\033[1;31mError: %s\033[0m\n", e.what());
        if(context.dumpHandle != NULL)
        {
            pcap_dump_close(context.dumpHandle);
        }
        if(handle != NULL)
        {
            pcap_close(handle);
        }
        nRet = -1;
    }
    catch(...)
    {
        printf("Unknown error\n");
        if(context.dumpHandle != NULL)
        {
            pcap_dump_close(context.dumpHandle);
        }
        if(handle != NULL)
        {
            pcap_close(handle);
        }
        nRet = -1;
    }

    return(nRet);
}    

void got_packet(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet)
{
    timeval frame;
    pcap_pkthdr* pHeader;
    ContextStruct* pContext = (ContextStruct*)arg;

    pContext->unStatCountTotal++;

    pHeader = new pcap_pkthdr();
    *pHeader = *header;
    pContext->vPacketsInFrame.push_back(pHeader);

    // Sliding Log time frame  
    // Move frame if needed by dropping packets from frame beginning
    for
    ( 
        timeval_subtract(&(header->ts), &(pContext->vPacketsInFrame.at(0)->ts), &frame);
        frame.tv_sec > 0; // frame size 1 second
        timeval_subtract(&(header->ts), &(pContext->vPacketsInFrame.at(0)->ts), &frame)
    )
    {
        pContext->unFrameAmount -= pContext->vPacketsInFrame.at(0)->len; // + pContext->vPacketsInFrame.at(0)->caplen;
        delete pContext->vPacketsInFrame.at(0);
        pContext->vPacketsInFrame.erase(pContext->vPacketsInFrame.begin());
    }

    printf
    (   
        "\rPackets total = %d, passed = %d, skipped = %d max rate = %.2f Mbps", 
        pContext->unStatCountTotal, 
        pContext->unStatCountPassed, 
        pContext->unStatCountSkipped,
        (pContext->unStatMaxRate/125000.0)
    );

    //  Rate control
    if((pContext->unFrameAmount + header->len) < pContext->unFrameLimit)
    {
        pContext->unFrameAmount += header->len; // + header->caplen;
        pcap_dump((u_char*)(pContext->dumpHandle), header, packet);
        pContext->unStatCountPassed++;
    }
    else
    {
        if(pContext->vPacketsInFrame.size() > 0)
        {
            delete pHeader;
            pContext->vPacketsInFrame.pop_back();
        }
        pContext->unStatCountSkipped++;
    }

    // Store max rate
    if(pContext->unStatMaxRate < pContext->unFrameAmount)
    {
        pContext->unStatMaxRate = pContext->unFrameAmount;
    }
}
