	
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
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
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
#include <time.h>
#include <pcap/pcap.h>
#include <err.h>
#include <pcap.h>
#include <errno.h>
#include <signal.h>
#include "ipk-scan.h"

#define BUFSIZE 65535
#define PCKT_LEN 8192
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif
#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

int n = 0;
pcap_t *handle;
int currentDstPort = -1;
//bool repeat = false;
int tcpCount = 0;


void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void pcapUdpHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char* argv[])
{
	/* setting up variables
	 * making sure every char* is set to '\0' */
	char c;
	bool puFlag = false, ptFlag = false, iFlag = false;
	const char *destinationName;
	char *interface, *SYN, *UDP, *dev;
	struct hostent *server;
	int udpPortList[BUFSIZE] = {-1};
	int tcpPortList[BUFSIZE] = {-1};
	char errbuf[PCAP_ERRBUF_SIZE];
	
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
	    		/*printf("option %s", long_options[option_index].name);
	    		if (optarg)
	    			printf(" with arg %s", optarg);*/
	    		//printf("\n");
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

	/* getting server adress */
	destinationName = argv[optind];
	//printf("destinationName: %s\n", destinationName);
	if ((server = gethostbyname(destinationName)) == NULL)
	{
		char *tmp = "ERROR: no such host as ";
		strcat(tmp, destinationName);
		errorMsg(tmp);
	}

	//inet_ntoa(*((struct in_addr*) server->h_addr_list[0]));
	struct in_addr addr;
	memcpy(&addr, server->h_addr_list[0], sizeof(struct in_addr)); 
	char destinationAddress[32];
	strcpy(destinationAddress, inet_ntoa(addr));
	
	if (puFlag)
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
		else
			udpPortList[0] = atoi(UDP);

	}

	if (ptFlag)
	{
		int index = 0;
		if (strstr(SYN, ",") != NULL)
		{
			char *ptr = strtok(SYN, ",");
			while (ptr != NULL)
			{
				printf("'%s'\n", ptr);
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



	//Create a raw socket
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	
	if (s == -1)
		errorMsg("ERROR: socket() failed");
	
	//packet to represent the packet
	char packet[PCKT_LEN] , source_ip[32], *pseudoTcpPacket;
	
	//zero out the packet buffer
	memset (packet, 0, PCKT_LEN);
	
	struct iphdr *iph = (struct iphdr *) packet;
	struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct ip));
	struct sockaddr_in sin;
	struct pseudoTcpHeader psh;
	
	if (iFlag)
		dev = interface;
	else if ((dev = pcap_lookupdev(errbuf)) == NULL)
    	err(1,"Can't open input device");

    //getting current IP address
    //inspired by https://stackoverflow.com/questions/1570511/c-code-to-get-the-ip-address
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s",dev);
    ioctl(fd, SIOCGIFADDR, &ifr);
    strcpy(source_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    close(fd);

	printf("%s\n", source_ip);
	sin.sin_family = AF_INET;
	//sin.sin_port = htons(80);
	sin.sin_addr.s_addr = inet_addr(destinationAddress);
	
	//int ID = 54321;
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
	iph->id = htonl (54321);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;
	
	//Ip checksum
	iph->check = csum ((unsigned short *) packet, iph->tot_len);
	
	//TCP Header
	tcph->source = htons (1234);
	//tcph->dest = htons (80);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;	//tcp header size
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;
	
	//Now the TCP checksum
	psh.src = inet_addr( source_ip );
	psh.dst = sin.sin_addr.s_addr;
	psh.res = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcpLen = htons(sizeof(struct tcphdr));
	
	int psize = sizeof(struct pseudoTcpHeader) + sizeof(struct tcphdr);
	pseudoTcpPacket = malloc(psize);
	
	memcpy(pseudoTcpPacket , (char*) &psh , sizeof (struct pseudoTcpHeader));
	//memcpy(pseudoTcpPacket + sizeof(struct pseudoTcpHeader) , tcph , sizeof(struct tcphdr));
	//tcph->check = csum((unsigned short*) pseudoTcpPacket, (sizeof(struct pseudoTcpHeader) + sizeof(struct tcphdr)));

	int one = 1;
	const int *val = &one;

    // Inform the kernel do not fill up the headers' structure, we fabricated our own
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
        errorMsg("ERROR: setsockopt() failed");
    //else
     //  printf("setsockopt() is OK\n");

    //printf("Using:::::Source IP: %s port: %u, Target IP: %s port: %u.\n", destinationName, tcpPortList[0], destinationName, tcpPortList[1]);

    // sendto() loop, send every 2 second for 50 counts
    //unsigned int count;
    /*for(count = 0; count < 20; count++)
    {
    	if(sendto(s, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
			errorMsg("ERROR: sendto() failed");
    	else
			printf("Count #%u - sendto() is OK\n", count);

    	sleep(2);
    }*/

    /*if(sendto(s, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		errorMsg("ERROR: sendto() failed");*/

   //close(s);
	//char errbuf[PCAP_ERRBUF_SIZE];  // constant defined in pcap.h
	//pcap_t *handle;                 // packet capture handle 
	//char *dev;                      // input device
	//struct in_addr a,b;
	bpf_u_int32 netaddr;            // network address configured at the input device
	bpf_u_int32 mask;               // network mask of the input device
	struct bpf_program fp;          // the compiled filter

	// open the device to sniff data
	/*if (iFlag)
		dev = interface;
	else if ((dev = pcap_lookupdev(errbuf)) == NULL)
    	err(1,"Can't open input device");*/

	// get IP address and mask of the sniffing interface
	if (pcap_lookupnet(dev,&netaddr,&mask,errbuf) == -1)
    	err(1,"pcap_lookupnet() failed");

	//a.s_addr=netaddr;
	//printf("Opening interface \"%s\" with net address %s,",dev,inet_ntoa(a));
	//b.s_addr=mask;
	//printf("mask %s for listening...\n",inet_ntoa(b));

	// open the interface for live sniffing
	if ((handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf)) == NULL)
    	err(1,"pcap_open_live() failed");

	// compile the filter
	if (pcap_compile(handle,&fp,"port 1234",0,netaddr) == -1)
    	err(1,"pcap_compile() failed");
  
	// set the filter to the packet capture handle
  	if (pcap_setfilter(handle,&fp) == -1)
    	err(1,"pcap_setfilter() failed");

  	// read packets from the interface in the infinite loop (count == -1)
  	// incoming packets are processed by function mypcap_handler()

    printf("PORT\t\tSTATE\n");

    for (; tcpPortList[tcpCount] > 0; tcpCount++)
    {
    	/*if (repeat)
    		i--;*/
    	sin.sin_port = htons(tcpPortList[tcpCount]);
		tcph->dest = htons (tcpPortList[tcpCount]);

		tcph->check = 0;
		memcpy(pseudoTcpPacket + sizeof(struct pseudoTcpHeader), tcph ,sizeof(struct tcphdr));
    	tcph->check = csum((unsigned short*) pseudoTcpPacket, (sizeof(struct pseudoTcpHeader) + sizeof(struct tcphdr)));

	    signal(SIGALRM, signalalarmTcpHandler);   
	    alarm(3);

		//tcph->check = csum((unsigned short*) pseudoTcpPacket, (sizeof(struct pseudoTcpHeader) + sizeof(struct tcphdr)));             
	    currentDstPort = tcpPortList[tcpCount];
	    if(sendto(s, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
			errorMsg("ERROR: sendto() failed");

	  	if (pcap_loop(handle, -1, mypcap_handler, NULL) == -1)
	    	err(1,"pcap_loop() failed");
	}

	iph->protocol = IPPROTO_UDP;
	iph->tot_len = sizeof (struct iphdr) + sizeof(struct udphdr);
	iph->check = csum ((unsigned short *) packet, iph->tot_len);
	char *pseudoUdpPacket;
	struct udphdr *udph = (struct udphdr *) (packet + sizeof(struct iphdr));
	memset(udph, 0, PCKT_LEN - sizeof(struct iphdr));
	udph->uh_sport = htons (1234); 
	udph->uh_ulen = htons(sizeof(struct udphdr));

	psize = sizeof(struct pseudoTcpHeader) + sizeof(struct udphdr);
	pseudoUdpPacket = malloc(psize);
	
	psh.protocol = IPPROTO_UDP;
	psh.tcpLen = htons(sizeof(struct udphdr));
	memcpy(pseudoUdpPacket , (char*) &psh , sizeof (struct pseudoTcpHeader));

	for (int i = 0; udpPortList[i] > 0; i++)
	{
		sin.sin_port = htons(udpPortList[i]);
		udph->uh_dport = htons(udpPortList[i]);
		udph->uh_sum = 0;

		memcpy(pseudoUdpPacket + sizeof(struct pseudoTcpHeader), udph, sizeof(struct udphdr));
    	udph->uh_sum = csum((unsigned short*) pseudoUdpPacket, (sizeof(struct pseudoTcpHeader) + sizeof(struct udphdr)));

    	signal(SIGALRM, signalalarmUdpHandler);   
	    alarm(3);

	   	currentDstPort = udpPortList[i];
	    if(sendto(s, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
			errorMsg("ERROR: sendto() failed");

	  	if (pcap_loop(handle, -1, pcapUdpHandler, NULL) == -1)
	    	err(1,"pcap_loop() failed");

	}

  	// close the capture device and deallocate resources
  	close(s);
  	pcap_close(handle);
  	free(pseudoUdpPacket);
  	free(pseudoTcpPacket);

    return 0;
}

void pcapUdpHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ip *my_ip;
	const struct icmp *my_icmp;
	u_int size_ip;

	my_ip = (struct ip*) (packet+SIZE_ETHERNET);
	size_ip = my_ip->ip_hl*4;
	if (my_ip->ip_p == 1)
	{
		my_icmp = (struct icmp*) (packet+SIZE_ETHERNET+size_ip);
		if (my_icmp->icmp_code == 3)
		{
			if (ntohs(currentDstPort) > 999)
	      		printf ("udp/%d\t", currentDstPort);
	      	else
	      		printf ("udp/%d\t\t", currentDstPort);
	      	red();
	      	printf("closed\n");
	      	reset();
	      	pcap_breakloop(handle);
		}
	}
}

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ip *my_ip;               // pointer to the beginning of IP header
	//struct ether_header *eptr;      // pointer to the beginning of Ethernet header
	const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
	//const struct udphdr *my_udp;    // pointer to the beginning of UDP header
	u_int size_ip;

    n++;
    // print the packet header data
    //printf("Packet no. %d:\n",n);
  	//printf("\tLength %d, received at %s",header->len,ctime((const time_t*)&header->ts.tv_sec));  
    // printf("Ethernet address length is %d\n",ETHER_HDR_LEN);
  
    // read the Ethernet header
    //eptr = (struct ether_header *) packet;
    my_ip = (struct ip*) (packet+SIZE_ETHERNET);
   	size_ip = my_ip->ip_hl*4;
    if (my_ip->ip_p == 6)
    {
    	my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip);
    	//printf("\tSrc port = %d, dst port = %d, seq = %u",ntohs(my_tcp->th_sport), ntohs(my_tcp->th_dport), ntohl(my_tcp->th_seq));
    	//printf ("tcp/%d", ntohs(my_tcp->th_dport));

		/*if (my_tcp->th_flags & TH_SYN)
			printf(", SYN");
		if (my_tcp->th_flags & TH_FIN)
			printf(", FIN");
		if (my_tcp->th_flags & TH_RST)
			printf(", RST");
		if (my_tcp->th_flags & TH_PUSH)
			printf(", PUSH");
		if (my_tcp->th_flags & TH_ACK)
			printf(", ACK");*/
    	if (currentDstPort == ntohs(my_tcp->th_sport))
    	{
	    	if ((my_tcp->th_flags & TH_SYN) && (my_tcp->th_flags & TH_ACK))
	    	{
	    		if (ntohs(my_tcp->th_sport) > 999)
	      			printf ("tcp/%d\t", ntohs(my_tcp->th_sport));
	      		else
	      			printf ("tcp/%d\t\t", ntohs(my_tcp->th_sport));
	      		green();
	      		printf("open\n");
	      		reset();
				//printf("\n");
	      		alarm(0);
	      		pcap_breakloop(handle);
	      	}

	      	else if ((my_tcp->th_flags & TH_RST) && (my_tcp->th_flags & TH_ACK))
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

      	/*else
      		//printf("\n");
      		alarm(0);
      		pcap_breakloop(handle);*/
      	//pcap_breakloop(handle);
    }
/*
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
  }*/ 
}

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

void signalalarmTcpHandler()
{
	static bool repeat = false;
	if (repeat)
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

unsigned short csum(unsigned short *ptr,int nbytes) 
{
	long sum = 0;
	unsigned short oddbyte;
	short answer;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum += (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}