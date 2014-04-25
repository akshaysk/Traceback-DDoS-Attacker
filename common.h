#ifndef _COMMON_H_
#define _COMMON_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <pthread.h>
#define MAXLOGSIZE	256
#define SIZE_ETHERNET 14
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define MAXIPADDRLEN	20
#define HOSTNAME	128
#define INFINITY	2147483647
#define BUFSIZE		25
#endif
