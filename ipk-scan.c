	
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
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <netdb.h>
#include <getopt.h>
#include "ipk-scan.h"

#define BUFSIZE 65535

int main(int argc, char* argv[])
{
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