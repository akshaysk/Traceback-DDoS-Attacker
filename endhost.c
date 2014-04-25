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

	if(ob->routerfile == NULL || ob->tcpport == 0 || ob->udpport == 0 || ob->stopthresh == 0)
		LOG(stderr, ERROR, "\nError: Command line arguments for endhost tool not specified correctly\n");

}

void send_start_marking_msg(char *router_ip, int tcpport)
{
	int fd;
	struct sockaddr_in router_addr;
	struct hostent *router_ip_addr;
	struct in_addr * address;
	socklen_t alen = sizeof(router_addr);
	
	char my_message[BUFSIZE], recv_message[BUFSIZE];
	memset(my_message, 0, BUFSIZE);
	memset(recv_message, 0, BUFSIZE);
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{ 
		LOG(stderr, ERROR, "cannot create socket"); 
	}

	memset((char*)&router_addr, 0, sizeof(router_addr)); 
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

	snprintf(my_message,BUFSIZE,"startMarking");
	if(write(fd, my_message, BUFSIZE) < 0) 
	{
		close(fd);
		perror("Endhost: Error in write() for victim client");
		exit(0);
	}
	printf("StartMarking message is sent");
	if(read(fd, recv_message, BUFSIZE) < 0)
	{
		close(fd);
		perror("Endhost: Error in read() for victim client");
		exit(0);
	}
	printf("\nPhase 3: Victim Client received ACK \n");
	close(fd);

}


void receive_udp_traceback(struct command_line_args *object)
{
	int fd, len;
	struct sockaddr_in myAddr, srcAddr;
	struct hostent *localhost_ip_addr;
	struct in_addr *address;
	char traceback_msg[BUFSIZE];

	int i = 0;
	socklen_t addrlen = sizeof(srcAddr);

	memset((char *)&myAddr, 0, sizeof(myAddr)); 
	myAddr.sin_family = AF_INET; 
	
	localhost_ip_addr = gethostbyname("localhost");
	address = (struct in_addr *)localhost_ip_addr->h_addr;

	myAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*address));
	
	myAddr.sin_port = htons(object->udpport);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{ 
		perror("Endhost: Cannot create udp socket ");
	}

	if (bind(fd, (struct sockaddr *)&myAddr, sizeof(myAddr)) < 0) 
	{ 
		perror("Endhost: Victim client bind failed");
	}


	printf("\nPhase 1: EndHost has UDP port number %d and IP address %s\n",htons(myAddr.sin_port), inet_ntoa(*address));
	while( i++ != object->stopthresh )
	{
		memset(traceback_msg,0,BUFSIZE);
		while((len = recvfrom(fd, traceback_msg, BUFSIZE, 0, (struct sockaddr *)&srcAddr, &addrlen))<0)
		{
			printf("Endhost: Error in receiving traceback data");
			continue;
		}
		if(attack_indication == 0)
			i--;
		printf("\nEndhost has received traceback from Router\n");
	}
}


void send_message_routers(struct command_line_args *object)
{

	FILE *fp = fopen(object->routerfile, "r");
	char router_ip[MAXIPADDRLEN];
	while(fgets(router_ip, MAXIPADDRLEN, fp) != NULL)
	{
		send_start_marking_msg(router_ip, object->tcpport);
	}
	
}

void check_for_attack(struct command_line_args *object)
{
	int fd,len;
	struct sockaddr_in myAddr, srcAddr;
	struct hostent *my_ip_addr;
	struct in_addr *address;
	char buffer[BUFSIZE];
//	extern int file_server_exists;

	socklen_t addrlen = sizeof(srcAddr);

	memset(buffer,0,BUFSIZE);
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{ 
		LOG(stderr, ERROR, "Error: Cannot create socket of directory server");
	}

	memset((char *)&myAddr, 0, sizeof(myAddr)); 
	myAddr.sin_family = AF_INET; 
	
	my_ip_addr = gethostbyname("localhost");
	address = (struct in_addr *)my_ip_addr->h_addr;

	myAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*address));
	
	myAddr.sin_port = htons(61089);
	if (bind(fd, (struct sockaddr *)&myAddr, sizeof(myAddr)) < 0) 
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
		send_message_routers(object);
	}
	
	LOG(stdout, LOGL, "EndHost: Endhost tool has received attack detected udp message");



}


int main(int argc, char **argv)
{

	struct command_line_args object;
	char hostname[HOSTNAME];
	memset(hostname, 0, HOSTNAME);
	gethostname(hostname, sizeof(hostname));
	strcat(hostname, ".endhost.log");	

	fp_log = fopen(hostname, "w");
	
	parse_command_line(argc, argv, &object);
	pthread_create(&udp_traceback, 0, (void *)receive_udp_traceback, &object);
	
	pthread_create(&attack_checker, 0, (void *)check_for_attack, &object);	
	pthread_join(attack_checker, 0);
	pthread_join(udp_traceback,0);
	return 0;
}

