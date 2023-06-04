#ifndef tools_h
#define tools_h

#include <string>

int timeval_subtract (const struct timeval *x, const struct timeval *y, struct timeval *diff);
bool process_command_line(int argc, char** argv, std::string& infile, std::string& outfile, u_int& rateLimit);

#endif
