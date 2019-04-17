all: ipk-scan

ipk-scan: scan.c
	gcc scan.c -Wall -Wextra -o ipk-scan -g
