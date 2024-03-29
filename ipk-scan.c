	
/***************************
 * IPK projekt 2. *
 *  Peter Havan   *
 *   xhavan00     *
 *   ipk-scan.c   *
***************************/

/*********************************************************
* Inspired by exmaples IPK/ISA course files from FIT VUT *
**********************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <netdb.h>
#include <getopt.h>
#include <netinet/ether.h> 
#include <pcap/pcap.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <ifaddrs.h>
#include "ipk-scan.h"

#define BUFSIZE 65535
#define PCKT_LEN 8192
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif
#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

pcap_t *handle;
int currentDstPort = -1;
int tcpCount = 0;

void pcapTcpHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void pcapUdpHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char* argv[])
{
	/* setting up variables */
	char c;
	bool puFlag = false, ptFlag = false, iFlag = false, ipv6Flag = false, ipv4Flag = false;
	char *interface, *SYN, *UDP, *dev;
	int udpPortList[BUFSIZE] = {-1};
	int tcpPortList[BUFSIZE] = {-1};
	char errbuf[PCAP_ERRBUF_SIZE], destinationAddress[100], sourceIp4[32], sourceIp6[50];
	
	/* checking arguments */
	if (argc < 2)
		errorMsg("ERROR: Invalid options");
	/*****************************************
	* Parsing arguments, getopt() is not 	*
	* sufficient, arguments -pu and -pt 	*
	* are long                              *
	*****************************************/
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
	    		if (!strcmp(long_options[option_index].name, "pu"))
	    		{
	   		 		UDP = strdup(optarg);
	   		 		puFlag = true;
	    		}
	   		 	else
	   		 	{
	   		 		SYN = strdup(optarg);
	   		 		ptFlag = true;
	   		 	}
	    		break;
	    	case 'i':
	    		iFlag = true;
	    		interface = strdup(optarg);
	    		break;
	    	default:
	    		errorMsg("ERROR: Invalid options");
	    }
	}
	/* no ports were specified */
	if (!(puFlag | ptFlag))
		errorMsg("ERROR: invalid options");

	/* getting server adress */
	/* inspired by https://gist.github.com/jirihnidek/bf7a2363e480491da72301b228b35d5d by jirihnidek */
	/******************************************************************
	* gethostbyname() cant deal with IPv6, we need to use getaddrinfo *
	******************************************************************/
  	struct addrinfo hints, *res;
  	int errcode;
  	void *ptr;
  	memset (&hints, 0, sizeof (hints));
  	hints.ai_family = PF_UNSPEC;
  	hints.ai_socktype = SOCK_STREAM;
  	hints.ai_flags |= AI_CANONNAME;
  	errcode = getaddrinfo (argv[optind], NULL, &hints, &res);
  	if (errcode != 0)
  		errorMsg("ERROR: gettaddrinfo()");
  	while (res)
    {
    	inet_ntop (res->ai_family, res->ai_addr->sa_data, destinationAddress, 100);
      	switch (res->ai_family)
        {
        	case AF_INET: //found IPv4 address
        		ipv4Flag = true;
          		ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
          		break;
        	case AF_INET6: //found IPv6 address
        		ipv6Flag = true;
          		ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
          		break;
        }
      	inet_ntop (res->ai_family, ptr, destinationAddress, 100);
      	res = res->ai_next;
      	if (ipv4Flag) // IPv4 is prefered in case argument was not IP address but hostname
      	{
      		break;
      	}
    }

    // parsing through UDP port argument
	if (puFlag)
	{
		int index = 0;
		if (strstr(UDP, ",") != NULL)
		{
			char *ptr = strtok(UDP, ",");
			while (ptr != NULL)
			{
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
		else
			udpPortList[0] = atoi(UDP);
	}

	// parsing through TCP port argument
	if (ptFlag)
	{
		int index = 0;
		if (strstr(SYN, ",") != NULL)
		{
			char *ptr = strtok(SYN, ",");
			while (ptr != NULL)
			{
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
		else
			tcpPortList[0] = atoi(SYN);
	}

	// setting up device
	if (iFlag)
		dev = interface;
	else if ((dev = pcap_lookupdev(errbuf)) == NULL)
    	errorMsg("ERROR: pcap_lookupdev() failed");

    //getting address on the interface, inspired by
    //https://stackoverflow.com/questions/33125710/how-to-get-ipv6-interface-address-using-getifaddr-function
	struct ifaddrs *ifa, *ifa_tmp;
	char sourceAddress[50];
	if (getifaddrs(&ifa) == -1) 
	    errorMsg("ERROR: getifaddrs() failed");
	ifa_tmp = ifa;
	while (ifa_tmp) 
	{
    	if ((ifa_tmp->ifa_addr) && ((ifa_tmp->ifa_addr->sa_family == AF_INET) ||
                              (ifa_tmp->ifa_addr->sa_family == AF_INET6))) 
    	{
        	if (ifa_tmp->ifa_addr->sa_family == AF_INET) 
        	{
            	// create IPv4 string
            	if (!strcmp(ifa_tmp->ifa_name, dev))
            	{
            		struct sockaddr_in *in = (struct sockaddr_in*) ifa_tmp->ifa_addr;
            		inet_ntop(AF_INET, &in->sin_addr, sourceAddress, sizeof(sourceAddress));
            		strcpy(sourceIp4, sourceAddress);
            	}
        	}

        	else 
        	{
            	// create IPv6 string
            	if (!strcmp(ifa_tmp->ifa_name, dev))
            	{
            		struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
            		inet_ntop(AF_INET6, &in6->sin6_addr, sourceAddress, sizeof(sourceAddress));
            		strcpy(sourceIp6, sourceAddress);
            		break;
            	}
        	}
    	}
    	ifa_tmp = ifa_tmp->ifa_next;
	}

	if (ipv4Flag) // if IPv4 destinationAddress was found, we'll use that
		sendV4Packet(sourceIp4, destinationAddress, udpPortList, tcpPortList, dev);
	else
		sendV6Packet(sourceIp6, destinationAddress, udpPortList, tcpPortList, dev);
    return 0;
}

/* Sending IPv6 packet */
void sendV6Packet(char *sourceIp6, char *destinationAddress, int *udpPortList, int *tcpPortList, char *dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char packet[PCKT_LEN], *pseudoTcpPacket, *pseudoUdpPacket;
	//zero out the packet buffer
	memset (packet, 0, PCKT_LEN);	
	struct ip6_hdr *iph = (struct ip6_hdr *) packet;
	struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct ip6_hdr));
	struct sockaddr_in6 sin = { 0 };
	struct pseudoHeaderV6 psh;

	inet_pton(AF_INET6, destinationAddress, &sin.sin6_addr);
	sin.sin6_family = AF_INET6;

	// create IPv6 header
	iph->ip6_plen = htons(sizeof(struct tcphdr));
	iph->ip6_nxt = IPPROTO_TCP;
	iph->ip6_hops = 255;
	iph->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0); //value for taken flow from https://blog.apnic.net/2017/10/24/raw-sockets-ipv6/
	inet_pton(AF_INET6, sourceIp6, &iph->ip6_src);
	inet_pton(AF_INET6, destinationAddress, &iph->ip6_dst);

	// create TCP header
	tcph->source = htons (1234);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;	//tcp header size
	tcph->fin=0;
	tcph->syn=1; //for SYN scanning
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (BUFSIZE); 
	tcph->check = 0; // cheksum filled later
	tcph->urg_ptr = 0;

	// create pseudo header
	inet_pton(AF_INET6, sourceIp6, &psh.src);
	inet_pton(AF_INET6, destinationAddress, &psh.dst);
	psh.len = htons(sizeof(struct tcphdr));
	psh.zeros = 0;
	psh.next = IPPROTO_TCP;

	int psize = sizeof(struct pseudoHeaderV6) + sizeof(struct tcphdr);
	pseudoTcpPacket = malloc(psize);
	
	memcpy(pseudoTcpPacket, (char*) &psh, sizeof(struct pseudoHeaderV6));

	int one = 1;
	const int *val = &one;
	//Create a raw socket
	//int s = socket (AF_INET6, SOCK_RAW, IPPROTO_TCP);
	int s = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (s == -1)
		errorMsg("ERROR: socket() failed");

    if(setsockopt(s, IPPROTO_IPV6, IPV6_HDRINCL, val, sizeof(one)) < 0)
        errorMsg("ERROR: setsockopt() failed");   

	bpf_u_int32 netaddr;            // network address configured at the input device
	bpf_u_int32 mask;               // network mask of the input device
	struct bpf_program fp;          // the compiled filter

	// get IP address and mask of the sniffing interface
	if (pcap_lookupnet(dev,&netaddr,&mask,errbuf) == -1)
    	err(1,"pcap_lookupnet() failed");

	// open the interface for live sniffing
	if ((handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf)) == NULL)
    	err(1,"pcap_open_live() failed");

	// compile the filter
	if (pcap_compile(handle,&fp,"port 1234",0,netaddr) == -1)
    	err(1,"pcap_compile() failed");
  
	// set the filter to the packet capture handle
  	if (pcap_setfilter(handle,&fp) == -1)
    	err(1,"pcap_setfilter() failed");

    printf("PORT\t\tSTATE\n");

    // loop through all TCP ports
    for (; tcpPortList[tcpCount] > 0; tcpCount++)
    {
    	// change ports
    	sin.sin6_port = htonl(tcpPortList[tcpCount]);
		tcph->dest = htons(tcpPortList[tcpCount]);;
		// calculate cheksum again based on ports
		tcph->check = 0;
		memcpy(pseudoTcpPacket + sizeof(struct pseudoHeaderV6), tcph, sizeof(struct tcphdr));
    	tcph->check = csum((unsigned short*) pseudoTcpPacket, (sizeof(struct pseudoHeaderV6) + sizeof(struct tcphdr)));
    	// set alarm, used as timeout
	    signal(SIGALRM, signalalarmTcpHandler);   
	    alarm(3);

	    currentDstPort = tcpPortList[tcpCount]; //global variable, used in handle

	    if((sendto(s, packet, sizeof(struct ip6_hdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&sin, sizeof(sin))) < 0) //send packet
			errorMsg("ERROR: sendto() failed");

	  	if (pcap_loop(handle, -1, pcapTcpHandler, NULL) == -1) //accept and analyze packet
	    	err(1,"pcap_loop() failed");
	}

	// change IP header for UDP
	iph->ip6_nxt = IPPROTO_UDP;
	iph->ip6_plen = sizeof(struct udphdr);
	// create UDP header
	struct udphdr *udph = (struct udphdr *) (packet + sizeof(struct ip6_hdr));
	memset(udph, 0, PCKT_LEN - sizeof(struct ip6_hdr));
	udph->uh_sport = htons (1234); 
	udph->uh_ulen = htons(sizeof(struct udphdr));

	// create UDP pseudo packet
	psize = sizeof(struct pseudoHeaderV6) + sizeof(struct udphdr);
	pseudoUdpPacket = malloc(psize);
	// we can reuse pseudo header from TCP
	psh.len = htons(sizeof(struct udphdr));
	psh.zeros = 0;
	psh.next = IPPROTO_UDP;
	memcpy(pseudoUdpPacket , (char*) &psh , sizeof (struct pseudoHeaderV6));

	// compile the filter
	if (pcap_compile(handle,&fp,"icmp",0,netaddr) == -1)
    	err(1,"pcap_compile() failed");
  
	// set the filter to the packet capture handle
  	if (pcap_setfilter(handle,&fp) == -1)
    	err(1,"pcap_setfilter() failed");

	for (int i = 0; udpPortList[i] > 0; i++)
	{
		// change ports ... sin.sin6_port must be htonl()
		sin.sin6_port = htonl(udpPortList[i]);
		udph->uh_dport = htons(udpPortList[i]);
		udph->uh_sum = 0;
		// calculate checksum after changing ports
		memcpy(pseudoUdpPacket + sizeof(struct pseudoHeaderV6), udph, sizeof(struct udphdr));
    	udph->uh_sum = csum((unsigned short*) pseudoUdpPacket, (sizeof(struct pseudoHeaderV6) + sizeof(struct udphdr)));
    	// setting up signal, used as timeout
    	signal(SIGALRM, signalalarmUdpHandler);   
	    alarm(3);
	   	currentDstPort = udpPortList[i]; //global variable, used in handle

	    if(sendto(s, packet, sizeof(struct ip6_hdr) + sizeof(struct udphdr), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) // sending packet
			errorMsg("ERROR: sendto() failed");

	  	if (pcap_loop(handle, -1, pcapUdpHandler, NULL) == -1) //accepting and analyzing packet
	    	err(1,"pcap_loop() failed");
	}

	// close the capture device and deallocate resources
  	close(s);
  	pcap_close(handle);
  	free(pseudoUdpPacket);
  	free(pseudoTcpPacket);
}

void sendV4Packet(char *sourceIp4, char *destinationAddress, int *udpPortList, int *tcpPortList, char *dev)
{

	char errbuf[PCAP_ERRBUF_SIZE];
	char packet[PCKT_LEN], *pseudoTcpPacket, *pseudoUdpPacket;
	//zero out the packet buffer
	memset (packet, 0, PCKT_LEN);	
	struct iphdr *iph = (struct iphdr *) packet;
	struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));
	struct sockaddr_in sin;
	struct pseudoHeader psh;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(destinationAddress);
	
	// create IPv4 header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
	iph->id = htonl (424242);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0; // set to zero before calculation
	iph->saddr = inet_addr ( sourceIp4 );
	iph->daddr = sin.sin_addr.s_addr;
	iph->check = csum ((unsigned short *) packet, iph->tot_len);
	
	// create TCP header
	tcph->source = htons (1234);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;	//tcp header size
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (PCKT_LEN);
	tcph->check = 0; // set to zero before calculation
	tcph->urg_ptr = 0;
	
	// create pseudo header
	psh.src = inet_addr( sourceIp4 );
	psh.dst = sin.sin_addr.s_addr;
	psh.res = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcpLen = htons(sizeof(struct tcphdr));
	
	int psize = sizeof(struct pseudoHeader) + sizeof(struct tcphdr);
	pseudoTcpPacket = malloc(psize);
	
	memcpy(pseudoTcpPacket , (char*) &psh , sizeof (struct pseudoHeader));

	int one = 1;
	const int *val = &one;

	//Create a raw socket
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (s == -1)
		errorMsg("ERROR: socket() failed");

    // Inform the kernel do not fill up the headers' structure, we fabricated our own
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        errorMsg("ERROR: setsockopt() failed");
    }

	bpf_u_int32 netaddr;            // network address configured at the input device
	bpf_u_int32 mask;               // network mask of the input device
	struct bpf_program fp;          // the compiled filter

	// get IP address and mask of the sniffing interface
	if (pcap_lookupnet(dev,&netaddr,&mask,errbuf) == -1)
    	err(1,"pcap_lookupnet() failed");

	// open the interface for live sniffing
	if ((handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf)) == NULL)
    	err(1,"pcap_open_live() failed");

	// compile the filter
	if (pcap_compile(handle,&fp,"port 1234",0,netaddr) == -1)
    	err(1,"pcap_compile() failed");
  
	// set the filter to the packet capture handle
  	if (pcap_setfilter(handle,&fp) == -1)
    	err(1,"pcap_setfilter() failed");

    printf("PORT\t\tSTATE\n");
    /* loop through TCP ports from the arguments */
    for (; tcpPortList[tcpCount] > 0; tcpCount++)
    {
    	/* change ports */
    	sin.sin_port = htons(tcpPortList[tcpCount]);
		tcph->dest = htons (tcpPortList[tcpCount]);
		/* calculate checksum after changing ports */
		tcph->check = 0;
		memcpy(pseudoTcpPacket + sizeof(struct pseudoHeader), tcph ,sizeof(struct tcphdr));
    	tcph->check = csum((unsigned short*) pseudoTcpPacket, (sizeof(struct pseudoHeader) + sizeof(struct tcphdr)));

    	// setting alarm, used as timeout
	    signal(SIGALRM, signalalarmTcpHandler);   
	    alarm(3);
	    currentDstPort = tcpPortList[tcpCount]; //global variable, used in the handler

	    if(sendto(s, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) //send packet
			errorMsg("ERROR: sendto() failed");
	  	if (pcap_loop(handle, -1, pcapTcpHandler, NULL) == -1) //accept and analyze packets
	    	err(1,"pcap_loop() failed");
	}

	/* change IP header for UDP values */
	iph->protocol = IPPROTO_UDP;
	iph->tot_len = sizeof (struct iphdr) + sizeof(struct udphdr);
	iph->check = csum ((unsigned short *) packet, iph->tot_len);
	struct udphdr *udph = (struct udphdr *) (packet + sizeof(struct iphdr));
	memset(udph, 0, PCKT_LEN - sizeof(struct iphdr));
	udph->uh_sport = htons (1234); 
	udph->uh_ulen = htons(sizeof(struct udphdr));

	/* create pseudo packet for UDP */
	/* we can reuse pseudo TCP header though with a few changed values */
	psize = sizeof(struct pseudoHeader) + sizeof(struct udphdr);
	pseudoUdpPacket = malloc(psize);
	psh.protocol = IPPROTO_UDP;
	psh.tcpLen = htons(sizeof(struct udphdr));
	memcpy(pseudoUdpPacket , (char*) &psh , sizeof (struct pseudoHeader));

	// compile the filter
	if (pcap_compile(handle,&fp,"icmp",0,netaddr) == -1)
    	err(1,"pcap_compile() failed");
  
	// set the filter to the packet capture handle
  	if (pcap_setfilter(handle,&fp) == -1)
    	err(1,"pcap_setfilter() failed");

    /* loop through all UDP ports from arguments */
	for (int i = 0; udpPortList[i] > 0; i++)
	{
		/* fix ports and calculate csum for new values */
		sin.sin_port = htons(udpPortList[i]);
		udph->uh_dport = htons(udpPortList[i]);
		udph->uh_sum = 0;
		memcpy(pseudoUdpPacket + sizeof(struct pseudoHeader), udph, sizeof(struct udphdr));
    	udph->uh_sum = csum((unsigned short*) pseudoUdpPacket, (sizeof(struct pseudoHeader) + sizeof(struct udphdr)));

    	/* set alarm, used as timeout */
    	signal(SIGALRM, signalalarmUdpHandler);   
	    alarm(3);
	   	currentDstPort = udpPortList[i]; //global variable, for usage in handler

	    if(sendto(s, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) //send packet
			errorMsg("ERROR: sendto() failed");

	  	if (pcap_loop(handle, -1, pcapUdpHandler, NULL) == -1) //analyze incoming packets
	    	err(1,"pcap_loop() failed");
	}

	// close the capture device and deallocate resources
  	close(s);
  	pcap_close(handle);
  	free(pseudoUdpPacket);
  	free(pseudoTcpPacket);

}

void pcapUdpHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ip *my_ip;
	const struct icmp *my_icmp;
	struct ether_header *eptr;      // pointer to the beginning of Ethernet header
	struct ip6_hdr *my_ip6;
	u_int size_ip;
	eptr = (struct ether_header *) packet;

	switch (ntohs(eptr->ether_type))
	{
		case ETHERTYPE_IP: //IPv4
			my_ip = (struct ip*) (packet+SIZE_ETHERNET);
			size_ip = my_ip->ip_hl*4;
			if (my_ip->ip_p == 1) //UDP
			{
				my_icmp = (struct icmp*) (packet+SIZE_ETHERNET+size_ip);
				if (my_icmp->icmp_code == 3) // port unreachable ICMP, closed
				{
					if (currentDstPort > 999)
			      		printf ("udp/%d\t", currentDstPort); 
			      	else
			      		printf ("udp/%d\t\t", currentDstPort);
			      	red();
			      	printf("closed\n");
			      	reset();
			      	pcap_breakloop(handle);
				}
			}
			break;
		case ETHERTYPE_IPV6: //IPv6
			my_ip6 = (struct ip6_hdr*) (packet+SIZE_ETHERNET);
			size_ip = sizeof(struct ip6_hdr);
			if (my_ip6->ip6_nxt == 1) //UDP
			{
				my_icmp = (struct icmp*) (packet+SIZE_ETHERNET+size_ip);
				if (my_icmp->icmp_code == 3) // port unreachable ICMP, closed
				{
					if (currentDstPort > 999)
			      		printf ("udp/%d\t", currentDstPort);
			      	else
			      		printf ("udp/%d\t\t", currentDstPort);
			      	red();
			      	printf("closed\n");
			      	reset();
			      	pcap_breakloop(handle);
				}
			}
			break;
	}
}

/* fuction for pcap_loop, accepting and analyzing TCP packets 
 * inspired by examples from ISA */
void pcapTcpHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ip *my_ip;               // pointer to the beginning of IP header
	const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
	struct ether_header *eptr;      // pointer to the beginning of Ethernet header
	struct ip6_hdr *my_ip6;
	u_int size_ip;
	eptr = (struct ether_header *) packet;

	switch (ntohs(eptr->ether_type)) //determine whether the packet is IPv4 or IPv6
	{
		case ETHERTYPE_IP: //IPv4
		    my_ip = (struct ip*) (packet+SIZE_ETHERNET);
		   	size_ip = my_ip->ip_hl*4;
		    if (my_ip->ip_p == 6) // TCP
		    {
		    	my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip);
		    	if (currentDstPort == ntohs(my_tcp->th_sport)) //coming from correct port
		    	{
			    	if ((my_tcp->th_flags & TH_SYN) && (my_tcp->th_flags & TH_ACK)) // OPEN, ACK and SYN flags are set
			    	{
			    		if (ntohs(my_tcp->th_sport) > 999)
			      			printf ("tcp/%d\t", ntohs(my_tcp->th_sport));
			      		else
			      			printf ("tcp/%d\t\t", ntohs(my_tcp->th_sport));
			      		green();
			      		printf("open\n");
			      		reset();
			      		alarm(0);
			      		pcap_breakloop(handle);
			      	}

			      	else if ((my_tcp->th_flags & TH_RST) && (my_tcp->th_flags & TH_ACK)) // CLOSED, RST flag is set
			      	{
			      		if (ntohs(my_tcp->th_sport) > 999)
			      			printf ("tcp/%d\t", ntohs(my_tcp->th_sport));
			      		else
			      			printf ("tcp/%d\t\t", ntohs(my_tcp->th_sport));
			      		red();
			      		printf("closed\n");
			      		reset();
			      		alarm(0);
			      		pcap_breakloop(handle);
			      	}
		      	}
		    }
		    break;

		case ETHERTYPE_IPV6: //IPv6
			my_ip6 = (struct ip6_hdr*) (packet+SIZE_ETHERNET);
			size_ip = sizeof(struct ip6_hdr);
			if (my_ip6->ip6_nxt == 6) //TCP
			{
				my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip);
				if (currentDstPort == ntohs(my_tcp->th_sport))
		    	{
			    	if ((my_tcp->th_flags & TH_SYN) && (my_tcp->th_flags & TH_ACK)) // OPEN, SYN and ACK flags are set
			    	{
			    		if (ntohs(my_tcp->th_sport) > 999)
			      			printf ("tcp/%d\t", ntohs(my_tcp->th_sport));
			      		else
			      			printf ("tcp/%d\t\t", ntohs(my_tcp->th_sport));
			      		green();
			      		printf("open\n");
			      		reset();
			      		alarm(0);
			      		pcap_breakloop(handle);
			      	}

			      	else if ((my_tcp->th_flags & TH_RST) && (my_tcp->th_flags & TH_ACK)) // CLOSED, RST flag is set
			      	{
			      		if (ntohs(my_tcp->th_sport) > 999)
			      			printf ("tcp/%d\t", ntohs(my_tcp->th_sport));
			      		else
			      			printf ("tcp/%d\t\t", ntohs(my_tcp->th_sport));
			      		red();
			      		printf("closed\n");
			      		reset();
			      		alarm(0);
			      		pcap_breakloop(handle);
			      	}
		      	}

			}
			break;

	}
}

/* timeout for UDP */
void signalalarmUdpHandler()
{
	if (currentDstPort > 999)
	    printf ("udp/%d\t", currentDstPort);
	else
	    printf ("udp/%d\t\t", currentDstPort);
	green();
	printf("open\n");
	reset();
	pcap_breakloop(handle);
}

/* timeout for TCP */
void signalalarmTcpHandler()
{
	static bool repeat = false;
	if (repeat) // resend request to make sure
	{
		if (ntohs(currentDstPort) > 999)
	    	printf ("tcp/%d\t\t", currentDstPort);
	    else
	      	printf ("tcp/%d\t\t", currentDstPort);
	    yellow();
	    printf("filtered\n"); 
	    reset();
	}
	else
		tcpCount--;
	repeat = !repeat;
	pcap_breakloop(handle);
}

/* Function is called when error occurs
 * Prints msg to stderr, exits with code 1 */
void errorMsg(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

/* adding some colors for nice output */
void red() {
  printf("\033[1;31m");
}

void green() {
  printf("\033[1;32m");
}

void yellow() {
  printf("\033[1;33m");
}

void reset() {
  printf("\033[0m");
}

//correct csum function, the one used in project recommended references had unexpected behaviour
//function borrowed from https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/ example
unsigned short csum(unsigned short *ptr, int nbytes) 
{
	long sum = 0;
	unsigned short oddbyte;
	short answer;
	while(nbytes>1) 
	{
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) 
	{
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}
	sum = (sum>>16)+(sum & 0xffff);
	sum += (sum>>16);
	answer=(short)~sum;
	return(answer);
}