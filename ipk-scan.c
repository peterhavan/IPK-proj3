	
/***************************
 * IPK projekt 2. *
 *  Peter Havan   *
 *   xhavan00     *
 *   ipk-scan.c     *
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

#define BUFSIZE 65535

/* Function is called when error occurs
 * Prints msg to stderr, exits with code 1 */
void errorMsg(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

int main(int argc, char* argv[])
{
	/* setting up variables
	 * making sure every char* is ten to '\0' */
	char option[2];
	int portNumber, optnumb = 0, clientSock, sent, recieved;
	char c;
	bool pu = false, pt = false, i = false, log = true;
	const char *hostName;
	char *interface, *SYN, *UDP;
	struct hostent *server;
	int udpPortList[BUFSIZE], tcpPortList[BUFSIZE];

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
	   		 		UDP = strdup(optarg);
	   		 	else
	   		 		SYN = strdup(optarg);
	    		break;

	    	case 'i':
	    		printf("option i\n");
	    		break;

	    	default:
	    		errorMsg("ERROR: Invalid options, default case");
	    }
	}


/*	while ((c = getopt(argc, argv, "i:p:")) != -1)
	{
		/* correct options / arguments */
/*		switch (c)
		{
			case 'i':
				interface = optarg;
				i = true;
				break;
			case 'p':
				printf("case p\n");
				pu = true;
				UDP = strdup(optarg);
				printf(optarg);
				printf("\n");
				printf("end of case p\n");
				break;
			case 'pt':
				pt = true;
				SYN = optarg;
				break;
			default:
				errorMsg("ERROR: Invalid options default");				
			/* incorrect options / arguments
			 * l has optional argument */
/*			default:
				switch (optopt)
				{
					case 'h':
					case 'p':
					case 'n':
					case 'f':
						errorMsg("Invalid options\n");
						break;
					case 'l':
                        log = false;
						strcat(option, "l");
						optnumb += 1;
						break;
					default:
						errorMsg("Invalid options\n");
				}

		}
	}*/
	



	/* checking whether all required options were passed */
	/*if (optnumb != 1 || !h || !p)
		errorMsg("Invalid options\n");
	/*



	/* getting server adress */
	hostName = argv[optind];

	if ((server = gethostbyname(hostName)) == NULL)
	{
		char *tmp = "ERROR: no such host as ";
		strcat(tmp, hostName);
		//strcat(tmp, "\n");
		errorMsg(tmp);
	}
	
	printf("before if UDP\n");
	if (UDP)
	{
		//char str[] = "strtok needs to be called several times to split a string";
		//int init_size = strlen(str);
		//char delim[] = "ai";
		printf("before strstr\n");
		if (strstr(UDP, ",") != NULL)
		{
			printf("before strtok \n");
			char *ptr = strtok(UDP, ",");
			printf("before while \n");
			while (ptr != NULL)
			{
				printf("'%s'\n", ptr);
				ptr = strtok(NULL, ",");
			}
		}
	}


}