all: ipk-scan

ipk-scan: ipk-scan.c
	gcc ipk-scan.c -Wall -o ipk-scan -g -lpcap
