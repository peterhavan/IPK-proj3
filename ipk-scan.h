    
/***************************
 * IPK projekt 2. *
 *  Peter Havan   *
 *   xhavan00     *
 *   ipk-scan.h   *
***************************/


#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


struct pseudoTcpHeader
{
    unsigned int src;
    unsigned int dst;
    unsigned char res;   
    unsigned char protocol;
    unsigned short int tcpLen;
};

unsigned short csum(unsigned short *ptr,int nbytes);

void errorMsg(char *msg);
void signalalarmTcpHandler();
void signalalarmUdpHandler();
void red();
void green();
void reset();
void yellow();
