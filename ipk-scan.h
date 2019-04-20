    
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


struct pseudoHeader
{
    unsigned int src;
    unsigned int dst;
    unsigned char res;   
    unsigned char protocol;
    unsigned short int tcpLen;
};

struct pseudoHeaderV6
{
    char src[16];
    char dst[16];
    unsigned int len;
    unsigned int zeros:24,
                 next:8;
};

unsigned short csum(unsigned short *ptr,int nbytes);
void sendV4Packet(char *sourceIp4, char *destinationAddress, int *udpPortList, int *tcpPortList, char *dev);
void sendV6Packet(char *sourceIp6, char *destinationAddress, int *udpPortList, int *tcpPortList, char *dev);
void errorMsg(char *msg);
void signalalarmTcpHandler();
void signalalarmUdpHandler();
void red();
void green();
void reset();
void yellow();
