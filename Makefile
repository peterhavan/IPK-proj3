all: ipk-scan

ipk-scan: ipk-scan.c
	gcc ipk-scan.c -o ipk-scan -g -lpcap
