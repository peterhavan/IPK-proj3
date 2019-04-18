all: ipk-scan

ipk-scan: ipk-scan.c
	gcc ipk-scan.c -Wall -Wextra -o ipk-scan -g -lpcap
