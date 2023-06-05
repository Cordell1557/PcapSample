#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <vector>
#include <string>

#include <pcap.h>

#include "tools.h"
#include "filterOfflineDevice.h"

int main(int argc, char *argv[])
{
    std::string infile; 
    std::string outfile; 
    u_int rateLimit = 0;
    int nRet = 0;

    try
    {
        if(process_command_line(argc, argv, infile, outfile, rateLimit))
        {
            nRet = filterOfflineDevice(infile, outfile, rateLimit);
        }
    }
    catch(std::exception& e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
        nRet = -1;
    }
    catch(...)
    {
        fprintf(stderr, "Unknown error\n");
        nRet = -1;
    }

    return(nRet);
}