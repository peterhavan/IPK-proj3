    
/***************************
 * IPK projekt 2. *
 *  Peter Havan   *
 *   xhavan00     *
 *   ipk-scan.h   *
***************************/


/*****************************************************
 *Inspired by https://www.tenouk.com/Module43a.html *
*****************************************************/

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// The IP header's structure
struct ipheader 
{
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    //unsigned char      iph_flag;
    //unsigned short int iph_offset;
    unsigned iph_flags:3;
    unsigned iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

 

// UDP header's structure

struct udpheader 
{
 unsigned short int udph_srcport;
 unsigned short int udph_destport;
 unsigned short int udph_len;
 unsigned short int udph_chksum;
};

/* Structure of a TCP header */
struct tcpheader 
{
    unsigned short int tcph_srcport;
    unsigned short int tcph_destport;
    unsigned int       tcph_seqnum;
    unsigned int       tcph_acknum;
    //unsigned char      tcph_reserved:4, tcph_offset:4;
    // unsigned char tcph_flags;
    unsigned int
        tcp_res1:4, /*little-endian*/
        tcph_hlen:4, /*length of tcp header in 32-bit words*/
        tcph_fin:1, /*Finish flag "fin"*/
        tcph_syn:1, /*Synchronize sequence numbers to start a connection*/
        tcph_rst:1, /*Reset flag */
        tcph_psh:1, /*Push, sends data to the application*/
        tcph_ack:1, /*acknowledge*/
        tcph_urg:1, /*urgent pointer*/
        tcph_res2:2;
    unsigned short int tcph_win;
    unsigned short int tcph_chksum;
    unsigned short int tcph_urgptr;
};

struct pseudoTcpHeader
{
    unsigned int src;
    unsigned int dst;
    unsigned char res;   
    unsigned char protocol;
    unsigned short int tcpLen;
};

//unsigned short csum(unsigned short *buf, int nwords);
unsigned short csum(unsigned short *ptr,int nbytes);

void errorMsg(char *msg);
