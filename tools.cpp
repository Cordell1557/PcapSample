#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <vector>
#include <string>

int timeval_subtract (const struct timeval *x, const struct timeval *y, struct timeval *diff)
{
    timeval sh = *y;    
    if (x->tv_usec < sh.tv_usec) 
    {
        int nsec = (sh.tv_usec - x->tv_usec) / 1000000 + 1;
        sh.tv_usec -= 1000000 * nsec;
        sh.tv_sec += nsec;
    }
    if (x->tv_usec - sh.tv_usec > 999999) 
    {      
        int nsec = (x->tv_usec - sh.tv_usec) / 1000000;
        sh.tv_usec += 1000000 * nsec;
        sh.tv_sec -= nsec;
    }
    diff->tv_sec = x->tv_sec - sh.tv_sec;
    diff->tv_usec = x->tv_usec - sh.tv_usec;

    return x->tv_sec < sh.tv_sec;
}

bool process_command_line(int argc, char** argv, std::string& infile, std::string& outfile, u_int& rateLimit)
{
    infile.clear();
    outfile.clear();
    rateLimit = 0;

    for(int i = 1; i < argc - 1; i++)
    {
        if(strcmp(argv[i], "-i") == 0)
        {
            infile = argv[++i];
            continue;
        }
        if(strcmp(argv[i], "-o") == 0)
        {
            outfile = argv[++i];
            continue;
        }
        if(strcmp(argv[i], "-l") == 0)
        {
            rateLimit = atoi(argv[++i]);
            continue;
        }
    }

    printf("Arguments: -i %s -o %s -l %d\n", infile.c_str(), outfile.c_str(), rateLimit);

    if
    (
        (infile.length() == 0) ||
        (outfile.length() == 0) ||
        (rateLimit == 0)
    )
    {
        printf("Usage: %s\n", argv[0]);
        printf("\t-h,--help\t\tShow this help message\n");
        printf("\t-i,--input\t\tinput file\n");
        printf("\t-o,--output\t\touput file\n");
        printf("\t-l,--limit\t\tlimimt in Mbps\n");
        printf("Sample: %s -i ./in.pcap -o ./out.pcap -l 100 \n", argv[0]);

        return(false);
    }
    return true;
}

void heartBeat()
{
    static const char* signArr = "-\\|/-\\|/";
    static u_int nIndex = 0;

    nIndex = (nIndex + 1)%strlen(signArr);

    printf("\r%c", signArr[nIndex]);
}
