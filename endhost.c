#include "endhost.h"
#include "log.h"

void parse_command_line(int argc, char **argv, struct command_line_args *ob)
{
	int opt = 0, longIndex = 0;
	memset(ob,'\0',sizeof(struct command_line_args));
	opt = getopt_long_only(argc, argv, ":r:t:u:s:", longOpts, &longIndex);
	if(opt == -1)
		LOG(stderr, ERROR, "usage: endhost [-r filename] [-t port] [-u por] [-s stopthresh] \n");
	while (opt != -1)
	{
		switch(opt) 
		{
			case 'r':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: endhost [-r filename] [-t port] [-u por] [-s stopthresh] \n");
				ob->routerfile = optarg;
				break;		
			case 't':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: endhost [-r filename] [-t port] [-u por] [-s stopthresh] \n");
				ob->tcpport = atoi(optarg);
				break;		
			case 'u':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: endhost [-r filename] [-t port] [-u por] [-s stopthresh] \n");
				ob->udpport = atoi(optarg);
				break;	
			case 's':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: endhost [-r filename] [-t port] [-u por] [-s stopthresh] \n");
				ob->stopthresh = atoi(optarg);
				break;

			case '?':
			case ':':
			default :
					LOG(stderr, ERROR, "usage: endhost [-r filename] [-t port] [-u por] [-s stopthresh] \n");

		}

	opt = getopt_long_only(argc, argv, ":r:t:u:s:", longOpts, &longIndex);
	}

	if(ob->tcpport == 0 || ob->udpport == 0 || ob->stopthresh == 0)
		LOG(stderr, ERROR, "\nError: Command line arguments for endhost tool not specified correctly\n");

}


void send_start_marking_msg(char *router_ip, int tcpport)
{
	int fd;
	struct sockaddr_in router_addr;
	struct hostent *router_ip_addr;
	struct in_addr * address;
	struct timeval curtime;
	socklen_t alen = sizeof(struct sockaddr_in);
	
	char my_message[BUFSIZE];
	memset(my_message, 0, BUFSIZE);
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{ 
		LOG(stderr, ERROR, "cannot create socket"); 
	}

	memset((char*)&router_addr, 0, sizeof(struct sockaddr_in)); 
	router_addr.sin_family = AF_INET; 
	router_addr.sin_port = htons(tcpport); 
	router_ip_addr = gethostbyname(router_ip);
	address = (struct in_addr *)router_ip_addr->h_addr;

	router_addr.sin_addr.s_addr = inet_addr(inet_ntoa(*address));
	
	if (connect(fd, (struct sockaddr *)&router_addr, alen) == -1) {
		close(fd);
		perror("TCP connection error");
		exit(0);
	}

	snprintf(my_message,BUFSIZE,"startMarking %s",router_ip);
	if(write(fd, my_message, BUFSIZE) < 0) 
	{
		close(fd);
		perror("Endhost: Error in write() for victim client");
		exit(0);
	}
	LOG(stdout, LOGL, "EndHost: StartMarking message is sent to Router(IP: %s, TCP: %d)",router_ip, tcpport);
	gettimeofday(&curtime, NULL);	
	LOG(fp_log, LOGL, "%f startMarking %s \'%s\'", SEC(TIME_IN_USEC(curtime)), router_ip,  my_message);
	close(fd);

}


void send_stop_marking_msg(char *router_ip, int tcpport)
{
	int fd;
	struct sockaddr_in router_addr;
	struct hostent *router_ip_addr;
	struct in_addr * address;
	socklen_t alen = sizeof(struct sockaddr_in);
	
	char my_message[BUFSIZE];
	memset(my_message, 0, BUFSIZE);
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{ 
		LOG(stderr, ERROR, "cannot create socket"); 
	}

	memset((char*)&router_addr, 0, sizeof(struct sockaddr_in)); 
	router_addr.sin_family = AF_INET; 
	router_addr.sin_port = htons(tcpport+1); 
	router_ip_addr = gethostbyname(router_ip);
	address = (struct in_addr *)router_ip_addr->h_addr;

	router_addr.sin_addr.s_addr = inet_addr(inet_ntoa(*address));
	
	if (connect(fd, (struct sockaddr *)&router_addr, alen) == -1) {
		close(fd);
		perror("TCP connection error");
		exit(0);
	}

	snprintf(my_message,BUFSIZE,"stopMarking");
	if(write(fd, my_message, BUFSIZE) < 0) 
	{
		close(fd);
		perror("Endhost: Error in write() for victim client");
		exit(0);
	}
	LOG(stdout, LOGL, "EndHost: StopMarking message is sent to Router(IP: %s, TCP: %d)",router_ip, tcpport);
	close(fd);

}

struct attacker_list *create_attackerlist_node(char *router_ip_addr, char *attacker_ip_addr, char *victim_ip_addr)
{
	struct attacker_list *newNode = (struct attacker_list *)malloc(sizeof(struct attacker_list));
	memset(newNode->attacker_ip_addr,'\0',MAXIPADDRLEN);
	memset(newNode->victim_ip_addr,'\0',MAXIPADDRLEN);
	strncpy(newNode->attacker_ip_addr, attacker_ip_addr, strlen(attacker_ip_addr)); 
	strncpy(newNode->victim_ip_addr, victim_ip_addr, strlen(victim_ip_addr)); 
	newNode->routerhead = (struct router_list *)malloc(sizeof(struct router_list));
	memset(newNode->routerhead,'\0',sizeof(struct router_list));
	strncpy(newNode->routerhead->router_ip, router_ip_addr, strlen(router_ip_addr));
	
	struct timeval curtime;
	gettimeofday(&curtime, NULL);
	LOG(fp_log, LOGL, "%f %s distance", SEC(TIME_IN_USEC(curtime)), router_ip_addr);
	newNode->routerhead->frequency = 1;
	newNode->routerhead->next = NULL;
	newNode->no_of_routers = 1;
	newNode->next = NULL; 
	return newNode;
}
void Create_Attacker_List(char *router_ip, char *attacker_ip, char * victim_ip)
{

	struct attacker_list *p;
	struct router_list *p_routerlist, *new_routerlist;
	if(routerAttackerHead == NULL)
	{
		routerAttackerHead = create_attackerlist_node(router_ip, attacker_ip, victim_ip);
	}

	else
	{
		p = routerAttackerHead;
		while(p != NULL)
		{
			if(strncmp(p->attacker_ip_addr, attacker_ip, MAXIPADDRLEN) == 0)
			{
				p_routerlist = p->routerhead;
				while(p_routerlist != NULL)
				{
					if(strncmp(p_routerlist->router_ip, router_ip, MAXIPADDRLEN) == 0)
					{
						p_routerlist->frequency++;
						goto end;
					}
					p_routerlist = p_routerlist->next;
				}
				if(p_routerlist == NULL)
				{
					new_routerlist = (struct router_list *)malloc(sizeof(struct router_list));
					memset(new_routerlist, '\0', sizeof(struct router_list));
					strncpy(new_routerlist->router_ip, router_ip, strlen(router_ip));
					new_routerlist->frequency = 1;
					new_routerlist->next = p->routerhead;
					p->routerhead = new_routerlist;
					p->no_of_routers++;
					struct timeval curtime;
					gettimeofday(&curtime, NULL);
					LOG(fp_log, LOGL, "%f %s distance", SEC(TIME_IN_USEC(curtime)), router_ip);
					goto end;
				}
			}
			p = p->next;	
		}
		end:	
		if(p == NULL)
		{
			p = create_attackerlist_node(router_ip, attacker_ip, victim_ip);
			p->next = routerAttackerHead;
			routerAttackerHead = p;
		}
	}
	

}

struct router_list * source_with_max_freq(struct router_list *routerhead)
{
	struct router_list *max_freq_router = routerhead, *p = routerhead;
	int max_freq = routerhead->frequency;
	while(p != NULL)
	{
		if(p->frequency > max_freq)
		{
			max_freq_router = p;
			max_freq = p->frequency;
		}

		p = p->next;
	}

	return max_freq_router;

}

struct router_list * delete_from_source_list(struct router_list *router_to_delete, struct router_list *routerhead)
{

	struct router_list *p;
	if(router_to_delete == routerhead)
	{
		routerhead = routerhead->next;
		router_to_delete->next = NULL;
		free(router_to_delete);
		return routerhead;
	}
	else
	{
		p = routerhead;
		while(p->next != router_to_delete)
			p = p->next;
		p->next = router_to_delete->next;
		router_to_delete->next = NULL;
		free(router_to_delete);
		return routerhead;
	}
}

void Path_Reconstruction()
{

	struct attacker_list *p = routerAttackerHead;
	struct router_list *q;
	struct hostent *router_ip_address;
	while( p != NULL)
	{

//		LOG(stdout, LOGL, "Victim:%s",p->victim_ip_addr);
//		LOG(stdout, LOGL, "Router:");
		fprintf(stdout, "\n%s,", p->victim_ip_addr);
		while( p->routerhead != NULL )
		{
			q = source_with_max_freq(p->routerhead);
//			LOG(stdout, LOGL, "%s,", q->router_ip);
			router_ip_address = gethostbyname(q->router_ip);
			fprintf(stdout, "%s,", router_ip_address->h_name);
//			fprintf(stdout, "%s", gethostnameq->routerhead);
			p->routerhead = delete_from_source_list(q, p->routerhead);
		}
//		LOG(stdout, LOGL, "Attacker:%s", p->attacker_ip_addr);
		fprintf(stdout, "%s", p->attacker_ip_addr);
		fflush(stdout);
		p = p->next;
	}	
}


void receive_udp_traceback(struct command_line_args *object)
{
	int fd, len;
	struct sockaddr_in myAddr, srcAddr;
	struct hostent *localhost_ip_addr;
	struct in_addr *address;
	char traceback_msg[BUFSIZE];
	char sign[BUFSIZE], router_ip[BUFSIZE], attacker_ip[BUFSIZE], victim_ip[BUFSIZE];
	int i = 0;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	memset((char *)&myAddr, 0, sizeof(struct sockaddr_in)); 
	myAddr.sin_family = AF_INET; 
	
	localhost_ip_addr = gethostbyname("0.0.0.0");
	address = (struct in_addr *)localhost_ip_addr->h_addr;

	myAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*address));
//	myAddr.sin_addr.s_addr = inet_addr("0.0.0.0");
	
	myAddr.sin_port = htons(object->udpport);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{ 
		perror("Endhost: Cannot create udp socket ");
	}

	if (bind(fd, (struct sockaddr *)&myAddr, sizeof(struct sockaddr_in)) < 0) 
	{ 
		perror("Endhost: Victim client bind failed");
	}


	printf("\nPhase 1: EndHost has UDP port number %d and IP address %s\n",htons(myAddr.sin_port), inet_ntoa(*address));
	while( i++ != object->stopthresh )
	{
		memset(traceback_msg,'\0',BUFSIZE);
		memset(router_ip,'\0',BUFSIZE);
		memset(sign, '\0', BUFSIZE);
		memset(attacker_ip,'\0',BUFSIZE);
		memset(victim_ip,'\0',BUFSIZE);
		memset((char *)&srcAddr, '\0', sizeof(struct sockaddr_in));
		while((len = recvfrom(fd, traceback_msg, BUFSIZE, 0, (struct sockaddr *)&srcAddr, &addrlen))<0)
		{
			printf("Endhost: Error in receiving traceback data");
			continue;
		}
		if(attack_indication == 0)
			i--;
		LOG(stdout, LOGL,"Endhost has received traceback from Router, %s",traceback_msg);
		sscanf(traceback_msg, "%s %s %s %s", sign, router_ip, attacker_ip, victim_ip);
		Create_Attacker_List(router_ip, attacker_ip, victim_ip);
	}
	send_stopMark_message_routers(object);
	Path_Reconstruction();
}

void check_for_attack(struct command_line_args *object)
{
	int fd,len;
	struct sockaddr_in myAddr, srcAddr;
	struct hostent *my_ip_addr;
	struct in_addr *address;
	char buffer[BUFSIZE];
//	extern int file_server_exists;
	char hostname[HOSTNAME];

	socklen_t addrlen = sizeof(struct sockaddr_in);

	memset(buffer,'\0',BUFSIZE);
	memset(hostname, '\0', HOSTNAME);
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{ 
		LOG(stderr, ERROR, "Error: Cannot create socket of directory server");
	}

	memset((char *)&myAddr, 0, sizeof(struct sockaddr_in)); 
	myAddr.sin_family = AF_INET; 
	gethostname(hostname, HOSTNAME);	
	my_ip_addr = gethostbyname(hostname);
	address = (struct in_addr *)my_ip_addr->h_addr;

	myAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*address));
	
	myAddr.sin_port = htons(61089);
	if (bind(fd, (struct sockaddr *)&myAddr, sizeof(struct sockaddr_in)) < 0) 
	{ 
		LOG(stderr, ERROR, "Error: EndHost tool bind failed");
	}

	while((len = recvfrom(fd, buffer, BUFSIZE, 0, (struct sockaddr *)&srcAddr, &addrlen))<0)
	{
		LOG(stderr, ERROR, "Error in receiving registration data");
		continue;
	}
	if(strncmp(buffer, "Attack_Detected", strlen(buffer)) == 0)
	{
		attack_indication = 1;
		LOG(stdout, LOGL, "Endhost: Received attack detected packet from Traffana");
		send_startMark_message_routers(object);
	}
		
	LOG(stdout, LOGL, "Check for attack ended");

}

void read_packets(u_char *object, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{

	const struct sniff_ip *ip;
	int version = 0;
	int size_ip = 0;
	char ip_addr[MAXIPADDRLEN], ip_src_addr[MAXIPADDRLEN];
	memset(ip_addr, '\0', MAXIPADDRLEN);
	memset(ip_src_addr, '\0', MAXIPADDRLEN);
	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	version = ip->ip_vhl >> 4;
	size_ip = IP_HL(ip)*4;	
	if(version != 4)
		return;
	if(size_ip < 20)
		return;


	sprintf(ip_src_addr, "%s",inet_ntoa(ip->ip_src));
	LOG(stdout, LOGL, "%s",ip_src_addr);

}
/*void determine_attacker_with_no_routers(struct command_line_args *object)
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
	if (handle == NULL) {
		LOG(stderr, ERROR, "Couldn't open device %s: %s", dev, errbuf);
	}
	pcap_loop(handle, -1, read_packets, NULL);
}
*/
void send_startMark_message_routers(struct command_line_args *object)
{

/*	if(object->routerfile == NULL && attack_indication == 1)
		determine_attacker_with_no_routers();
*/	
	FILE *fp = fopen(object->routerfile, "r");

	char router_ip[MAXIPADDRLEN];
	int len = 0;
	memset(router_ip, '\0', MAXIPADDRLEN);
	while(fgets(router_ip, MAXIPADDRLEN, fp) != NULL)
	{
		len = strlen(router_ip);
		router_ip[len - 1] = '\0';
		LOG(stdout, LOGL, "Router Ip : %s, TCP Port: %d",router_ip, object->tcpport);
		send_start_marking_msg(router_ip, object->tcpport);
	}
	fclose(fp);	
}

void send_stopMark_message_routers(struct command_line_args *object)
{

	FILE *fp = fopen(object->routerfile, "r");
	char router_ip[MAXIPADDRLEN];
	int len = 0;
	memset(router_ip, '\0', MAXIPADDRLEN);
	while(fgets(router_ip, MAXIPADDRLEN, fp) != NULL)
	{
		len = strlen(router_ip);
		router_ip[len - 1] = '\0';
		LOG(stdout, LOGL, "Router Ip : %s, TCP Port: %d",router_ip, object->tcpport);
		send_stop_marking_msg(router_ip, object->tcpport);
	}
	fclose(fp);	
}



int main(int argc, char **argv)
{

	struct command_line_args object;
	char hostname[HOSTNAME];
	memset(hostname, 0, HOSTNAME);
	gethostname(hostname, HOSTNAME);
	strcat(hostname, ".endhost.log");	

	fp_log = fopen(hostname, "w");
	
	parse_command_line(argc, argv, &object);
	pthread_create(&udp_traceback, 0, (void *)receive_udp_traceback, &object);
	
	pthread_create(&attack_checker, 0, (void *)check_for_attack, &object);	
	pthread_join(attack_checker, 0);
	pthread_join(udp_traceback,0);
	return 0;
}

