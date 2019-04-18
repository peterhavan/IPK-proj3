	
/***************************
 * IPK projekt 2. *
 *  Peter Havan   *
 *   xhavan00     *
 *   ipk-scan.c   *
***************************/

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <netdb.h>
#include <getopt.h>
#include <netinet/ether.h> 
#include <time.h>
#include <pcap/pcap.h>
#include <err.h>
#include <pcap.h>
#include <errno.h>
#include "ipk-scan.h"

#define BUFSIZE 65535
#define PCKT_LEN 8192
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif
#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol
int n = 0;

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char* argv[])
{
	printf("%zu\n\n", sizeof(struct tcpheader));
	/* setting up variables
	 * making sure every char* is set to '\0' */
	//char option[2];
	//int portNumber, optnumb = 0, clientSock, sent, recieved;
	char c;
	bool pu = false, pt = false, i = false;
	const char *hostName;
	char *interface, *SYN, *UDP;
	struct hostent *server;
	int udpPortList[BUFSIZE] = {-1};
	int tcpPortList[BUFSIZE] = {-1};

	//struct sockaddr_in serverAdd;
	//char buffer[BUFSIZE];
	//bzero(option, 2);
	//bzero(login, BUFSIZE);
	
	/* checking arguments */
	if (argc < 2)
		errorMsg("ERROR: Invalid options");

	while (1) 
	{
		int option_index = 0;
		static struct option long_options[] = {
	   		{"pt", required_argument, 0, 0},
	    	{"pu", required_argument, 0, 0},
	    	{0, 0, 0, 0} };

	    c = getopt_long_only(argc, argv, "i:", long_options, &option_index);
	    	if (c == -1)
	        	break;
	    switch (c)
	    {
	    	case 0:
	    		printf("option %s", long_options[option_index].name);
	    		if (optarg)
	    			printf(" with arg %s", optarg);
	    		printf("\n");
	    		if (!strcmp(long_options[option_index].name, "pu"))
	    		{
	   		 		UDP = strdup(optarg);
	   		 		pu = true;
	    		}
	   		 	else
	   		 	{
	   		 		SYN = strdup(optarg);
	   		 		pt = true;
	   		 	}
	    		break;

	    	case 'i':
	    		printf("option i\n");
	    		break;

	    	default:
	    		errorMsg("ERROR: Invalid options, default case");
	    }
	}

	/* getting server adress */
	hostName = argv[optind];
	if ((server = gethostbyname(hostName)) == NULL)
	{
		char *tmp = "ERROR: no such host as ";
		strcat(tmp, hostName);
		errorMsg(tmp);
	}
	
	if (pu)
	{
		int index = 0;
		if (strstr(UDP, ",") != NULL)
		{
			char *ptr = strtok(UDP, ",");
			while (ptr != NULL)
			{
				//printf("'%s'\n", ptr);
				udpPortList[index] = atoi(ptr);	
				ptr = strtok(NULL, ",");
				index++;
			}
		}

		else if (strstr(UDP, "-") != NULL)
		{
			char *ptr = strtok(UDP, "-");
			int from = atoi(ptr);
			ptr = strtok(NULL, "-");
			int to = atoi(ptr);
			for (int i = 0; i <= (to-from); i++)
				udpPortList[i] = from+i;

		}
	}

	if (pt)
	{
		int index = 0;
		if (strstr(SYN, ",") != NULL)
		{
			char *ptr = strtok(SYN, ",");
			while (ptr != NULL)
			{
				//printf("'%s'\n", ptr);
				tcpPortList[index] = atoi(ptr);
				ptr = strtok(NULL, ",");
				index++;
			}
		}

		else if (strstr(SYN, "-") != NULL)
		{

			char *ptr = strtok(SYN, "-");
			int from = atoi(ptr);
			ptr = strtok(NULL, "-");
			int to = atoi(ptr);
			for (int i = 0; i <= (to-from); i++)
				tcpPortList[i] = from+i;
		}
	}

	for (int i = 0; udpPortList[i] > 0; i++)
		printf("%d, ", udpPortList[i]);
	printf("\n");

	for (int i = 0; tcpPortList[i] > 0; i++)
		printf("%d, ", tcpPortList[i]);
	printf("\n");

    int sd;
    // No data, just datagram
    char buffer[PCKT_LEN];
    char psBuffer[PCKT_LEN];

    // The size of the headers
    struct ipheader *ip = (struct ipheader *) buffer;
    struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    memset(buffer, 0, PCKT_LEN);
    memset(psBuffer, 0, PCKT_LEN);
	
	/*if (argc != 5)
    {
    	printf("- Invalid parameters!!!\n");
    	printf("- Usage: %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n", argv[0]);
    	exit(-1);
    }*/    

    sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sd < 0)
    {
       perror("socket() error");
       exit(-1);
    }
    else
    	printf("socket()-SOCK_RAW and tcp protocol is OK.\n");  

    // The source is redundant, may be used later if needed
    // Address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    // Source port, can be any, modify as needed
    sin.sin_port = htons(tcpPortList[0]);
    din.sin_port = htons(tcpPortList[1]);

    // Source IP, can be any, modify as needed
    sin.sin_addr.s_addr = inet_addr("127.0.1.1");
    din.sin_addr.s_addr = inet_addr(hostName);

    // IP structure
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0;
    ip->iph_len = sizeof(struct ipheader) + sizeof(struct tcpheader);
    ip->iph_ident = htons(54321);
    ip->iph_offset = 0;
    ip->iph_ttl = 64;
    ip->iph_protocol = 6; // TCP
    ip->iph_chksum = 0; // Done by kernel

    // Source IP, modify as needed, spoofed, we accept through command line argument
    ip->iph_sourceip = inet_addr("127.0.1.1");

    // Destination IP, modify as needed, but here we accept through command line argument
    ip->iph_destip = inet_addr(hostName);

    //Pseudo TCP header for checksum
    //struct ipheader *ip = (struct ipheader *) buffer;
    //struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));
    struct pseudoTcpHeader *pseTcp = (struct pseudoTcpHeader *) psBuffer;
    struct tcpheader *tmpTcp = (struct tcpheader *) (psBuffer + sizeof(struct pseudoTcpHeader));
    memcpy(tmpTcp, tcp, sizeof(struct tcpheader));
    pseTcp->src = ip->iph_sourceip;
    pseTcp->dst = ip->iph_destip;
    pseTcp->res = 0;
    pseTcp->protocol = ip->iph_protocol;
    pseTcp->tcpLen = htons((sizeof(struct tcpheader)));
     
     /*struct pseudoTcpHeader
{
    unsigned int src;
    unsigned int dst;
    unsigned char res;   
    unsigned char protocol;
    unsigned short int tcpLen;
};*/

    // The TCP structure. The source port, spoofed, we accept through the command line
    tcp->tcph_srcport = htons(tcpPortList[0]);
    // The destination port, we accept through command line
    tcp->tcph_destport = htons(tcpPortList[1]);
    tcp->tcph_seqnum = 0;
    tcp->tcph_acknum = 0;
    //tcp->tcph_offset = 5;
    tcp->tcph_hlen = 5;
    tcp->tcph_syn = 1;
    tcp->tcph_ack = 0;
    tcp->tcph_win = htons(32767);
    tcp->tcph_chksum = 0; // Done by kernel
    //tcp->tcph_chksum = csum((unsigned short *) tcp, sizeof(struct tcpheader));
    tcp->tcph_urgptr = 0;
    tcp->tcph_chksum = csum((unsigned short *) psBuffer, (sizeof(struct tcpheader) + sizeof(struct pseudoTcpHeader)));

    // IP checksum calculation
    ip->iph_chksum = csum((unsigned short *) buffer, (sizeof(struct ipheader) + sizeof(struct tcpheader)));

    // Inform the kernel do not fill up the headers' structure, we fabricated our own
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("setsockopt() error");
        exit(-1);
    }
    else
       printf("setsockopt() is OK\n");

    printf("Using:::::Source IP: %s port: %u, Target IP: %s port: %u.\n", hostName, tcpPortList[0], hostName, tcpPortList[1]);

    // sendto() loop, send every 2 second for 50 counts
    unsigned int count;
    for(count = 0; count < 20; count++)
    {
    	if(sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    	// Verify
    	{
			perror("sendto() error");
			exit(-1);
    	}

    	else
			printf("Count #%u - sendto() is OK\n", count);

    	sleep(2);
    }
	/*if(sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	// Verify
	{
		perror("sendto() error");
		exit(-1);
	}

	else
		printf("Count #%u - sendto() is OK\n", count);*/

    close(sd);

	char errbuf[PCAP_ERRBUF_SIZE];  // constant defined in pcap.h
	pcap_t *handle;                 // packet capture handle 
	char *dev;                      // input device
	struct in_addr a,b;
	bpf_u_int32 netaddr;            // network address configured at the input device
	bpf_u_int32 mask;               // network mask of the input device
	struct bpf_program fp;          // the compiled filter

	// open the device to sniff data
	if ((dev = pcap_lookupdev(errbuf)) == NULL)
    	err(1,"Can't open input device");

	// get IP address and mask of the sniffing interface
	if (pcap_lookupnet(dev,&netaddr,&mask,errbuf) == -1)
    	err(1,"pcap_lookupnet() failed");

	a.s_addr=netaddr;
	printf("Opening interface \"%s\" with net address %s,",dev,inet_ntoa(a));
	b.s_addr=mask;
	printf("mask %s for listening...\n",inet_ntoa(b));

	// open the interface for live sniffing
	if ((handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf)) == NULL)
    	err(1,"pcap_open_live() failed");

	// compile the filter
	if (pcap_compile(handle,&fp,"port 23",0,netaddr) == -1)
    	err(1,"pcap_compile() failed");
  
	// set the filter to the packet capture handle
  	if (pcap_setfilter(handle,&fp) == -1)
    	err(1,"pcap_setfilter() failed");

  	// read packets from the interface in the infinite loop (count == -1)
  	// incoming packets are processed by function mypcap_handler() 
  	if (pcap_loop(handle,-1,mypcap_handler,NULL) == -1)
    	err(1,"pcap_loop() failed");

  	// close the capture device and deallocate resources
  	pcap_close(handle);


    return 0;
}

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ip *my_ip;               // pointer to the beginning of IP header
  struct ether_header *eptr;      // pointer to the beginning of Ethernet header
  const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
  const struct udphdr *my_udp;    // pointer to the beginning of UDP header
  u_int size_ip;

  n++;
  // print the packet header data
  printf("Packet no. %d:\n",n);
  printf("\tLength %d, received at %s",header->len,ctime((const time_t*)&header->ts.tv_sec));  
  //    printf("Ethernet address length is %d\n",ETHER_HDR_LEN);
  
  // read the Ethernet header
  eptr = (struct ether_header *) packet;
  printf("\tSource MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_shost)) ;
  printf("\tDestination MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost)) ;
  
  switch (ntohs(eptr->ether_type)){               // see /usr/include/net/ethernet.h for types
  case ETHERTYPE_IP: // IPv4 packet
    printf("\tEthernet type is  0x%x, i.e. IP packet \n", ntohs(eptr->ether_type));
    my_ip = (struct ip*) (packet+SIZE_ETHERNET);        // skip Ethernet header
    size_ip = my_ip->ip_hl*4;                           // length of IP header

    printf("\tIP: id 0x%x, hlen %d bytes, version %d, total length %d bytes, TTL %d\n",ntohs(my_ip->ip_id),size_ip,my_ip->ip_v,ntohs(my_ip->ip_len),my_ip->ip_ttl);
    printf("\tIP src = %s, ",inet_ntoa(my_ip->ip_src));
    printf("IP dst = %s",inet_ntoa(my_ip->ip_dst));
    
    switch (my_ip->ip_p){
    case 2: // IGMP protocol
      printf(", protocol IGMP (%d)\n",my_ip->ip_p);
      break;
    case 6: // TCP protocol
      printf(", protocol TCP (%d)\n",my_ip->ip_p);
      my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the TCP header
      printf("\tSrc port = %d, dst port = %d, seq = %u",ntohs(my_tcp->th_sport), ntohs(my_tcp->th_dport), ntohl(my_tcp->th_seq));
      if (my_tcp->th_flags & TH_SYN)
	printf(", SYN");
      if (my_tcp->th_flags & TH_FIN)
	printf(", FIN");
      if (my_tcp->th_flags & TH_RST)
	printf(", RST");
      if (my_tcp->th_flags & TH_PUSH)
	printf(", PUSH");
      if (my_tcp->th_flags & TH_ACK)
	printf(", ACK");
      printf("\n");
      break;
    case 17: // UDP protocol
      printf(", protocol UDP (%d)\n",my_ip->ip_p);
      my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the UDP header
      printf("\tSrc port = %d, dst port = %d, length %d\n",ntohs(my_udp->uh_sport), ntohs(my_udp->uh_dport), ntohs(my_udp->uh_ulen));
      break;
    default: 
      printf(", protocol %d\n",my_ip->ip_p);
    }
    break;
    
  case ETHERTYPE_IPV6:  // IPv6
    printf("\tEthernet type is 0x%x, i.e., IPv6 packet\n",ntohs(eptr->ether_type));
    break;
  case ETHERTYPE_ARP:  // ARP
    printf("\tEthernet type is 0x%x, i.e., ARP packet\n",ntohs(eptr->ether_type));
    break;
  default:
    printf("\tEthernet type 0x%x, not IPv4\n", ntohs(eptr->ether_type));
  } 
}


/* Function is called when error occurs
 * Prints msg to stderr, exits with code 1 */
void errorMsg(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

/* function from https://www.tenouk.com/Module43a.html */
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
    {
        sum += *buf++;	
    }
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}