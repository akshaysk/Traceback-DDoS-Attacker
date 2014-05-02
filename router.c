#include "router.h"
#include "log.h"
pthread_t marker_thread, listener_for_stop;

void parse_command_line(int argc, char **argv, struct command_line_args *ob)
{
	int opt = 0, longIndex = 0;
	memset(ob,'\0',sizeof(struct command_line_args));
	opt = getopt_long_only(argc, argv, ":e:t:u:p:", longOpts, &longIndex);
	if(opt == -1)
		LOG(stderr, ERROR, "usage: router [-e epoch] [-t port] [-u por] [-p prob] \n");
	while (opt != -1)
	{
		switch(opt) 
		{
			case 'e':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: router [-e epoch] [-t port] [-u por] [-p prob] \n");
				ob->epoch = atof(optarg);
				break;		
			case 't':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: router [-e epoch] [-t port] [-u por] [-p prob] \n");
				ob->tcpport = atoi(optarg);
				break;		
			case 'u':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: router [-e epoch] [-t port] [-u por] [-p prob] \n");
				ob->udpport = atoi(optarg);
				break;	
			case 'p':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: router [-e epoch] [-t port] [-u por] [-p prob] \n");
				ob->prob = atof(optarg);
				break;

			case '?':
			case ':':
			default :
					LOG(stderr, ERROR, "usage: router [-e epoch] [-t port] [-u por] [-p prob] \n");

		}

	opt = getopt_long_only(argc, argv, ":e:t:u:p:", longOpts, &longIndex);
	}

	if(ob->prob == 0 || ob->tcpport == 0 || ob->udpport == 0 || ob->epoch == 0)
		LOG(stderr, ERROR, "usage: router [-e epoch] [-t port] [-u por] [-p prob] \n");

}



void create_udp_traceback(char *ip_addr, char *attacker_ip_addr, int udpport, char *victim_ip_addr)
{

	struct sockaddr_in routerAddr,victimAddr;
	int fd, port_no;
	char my_message[BUFSIZE];
	struct hostent *router_ip_addr, *dest_ip_addr;
	struct in_addr * address;
	memset(my_message,0,BUFSIZE);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{ 
		perror("Phase 2: Error cannot create client server socket\n");
		exit(0);
	}
	memset((char *)&routerAddr, 0, sizeof(struct sockaddr_in)); 
	routerAddr.sin_family = AF_INET; 
	router_ip_addr = gethostbyname(ip_addr);
	address = (struct in_addr *)router_ip_addr->h_addr;

	routerAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*address));
	port_no = 58089;
	routerAddr.sin_port = htons(port_no);
/*	int ttl = 100;	
	setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));*/
	if(bind(fd, (struct sockaddr *)&routerAddr, sizeof(struct sockaddr_in)) < 0) 
	{ 
		perror("\nPhase 2: Client bind failed\n");
		exit(0);
	}

	memset((char *)&victimAddr, 0, sizeof(struct sockaddr_in)); 
	victimAddr.sin_family = AF_INET; 
 	dest_ip_addr = gethostbyname(victim_ip_addr);
	address = (struct in_addr *)dest_ip_addr->h_addr;

	victimAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*address));
	
	victimAddr.sin_port = htons(udpport);
	
	snprintf(my_message,BUFSIZE,"Traceback %s %s %s",ip_addr, attacker_ip_addr, victim_ip_addr);	
	LOG(stdout, LOGL, "%s", my_message);
	if(sendto(fd, my_message, strlen(my_message), 0, (struct sockaddr *)&victimAddr, sizeof(struct sockaddr_in)) < 0) 
		LOG(stderr, ERROR, "Error: Error in sendto() for traffana. Failed to send Attack Detected UDP message to endhost tool");

	LOG(stdout, LOGL, "Log: Traceback message is successfully sent to endhost tool(IP: %s, Port: %d)",victim_ip_addr, udpport);

	close(fd);

}

void read_and_mark_packets(u_char *obj, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	struct marker_structure *marker_obj = (struct marker_structure *)obj;
	const struct sniff_ip *ip;
	
	char ip_addr[MAXIPADDRLEN], attacker_ip_addr[MAXIPADDRLEN], victim_ip_addr[MAXIPADDRLEN];
	memset(ip_addr, '\0', MAXIPADDRLEN);
	memset(attacker_ip_addr, '\0', MAXIPADDRLEN);
	memset(victim_ip_addr, '\0', MAXIPADDRLEN);

	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET + 2);
	sprintf(victim_ip_addr, "%s", inet_ntoa(ip->ip_dst));
	sprintf(attacker_ip_addr, "%s", inet_ntoa(ip->ip_src));
	
	if(strncmp(attacker_ip_addr, marker_obj->ip_address , strlen(attacker_ip_addr)) == 0)
	{
		return;	
	}
	if(strncmp(victim_ip_addr, marker_obj->victim_ip_address , strlen(inet_ntoa(ip->ip_dst))) == 0)
	{
//		sprintf(ip_src_addr, "%s",inet_ntoa(ip->ip_src));
//		LOG(stdout, LOGL, "%s",ip_src_addr);
		LOG(stdout, LOGL, "Attacker IP: %s\t Victim IP: %s", attacker_ip_addr, victim_ip_addr);
		double prob_var = rand()/RAND_MAX;
		if(prob_var >= 0 && prob_var < marker_obj->cmd_object->prob)
		{
			create_udp_traceback(marker_obj->ip_address, attacker_ip_addr, marker_obj->cmd_object->udpport, victim_ip_addr);
		}
	}
}


void startMarking(struct command_line_args *object, char *ip_address, char *victim_ip_addr)
{

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	handle = pcap_open_live(NULL, BUFSIZ, 1, 0, errbuf);
	if (handle == NULL) {
		LOG(stderr, ERROR, "Couldn't open device");
	}
	
	LOG(stdout, LOGL, "StartMarking Has Started");
	struct marker_structure marker_obj;
	marker_obj.cmd_object = object;
	marker_obj.ip_address = ip_address;
	marker_obj.victim_ip_address = victim_ip_addr;
	marker_obj.handle = handle;
	pcap_loop(handle, -1, read_and_mark_packets, (u_char *)&marker_obj);
	
}

void wait_for_startMarking(struct command_line_args *object)
{
	int fd, rqst,len;
	struct sockaddr_in my_addr;
	struct sockaddr victim_address; 
	socklen_t victim_addr_len = sizeof(struct sockaddr);
	
	char buffer[BUFSIZE], victim_ip_address[BUFSIZE];
	char sign[BUFSIZE], ip_addr[BUFSIZE];
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{ 
		perror("cannot create socket"); 
		exit(0); 
	}

	memset((char*)&my_addr, 0, sizeof(struct sockaddr_in)); 
	my_addr.sin_family = AF_INET; 
	my_addr.sin_port = htons(object->tcpport); 

	my_addr.sin_addr.s_addr = inet_addr("0.0.0.0");

	if (bind(fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in)) < 0) 
	{
		perror("bind failed"); 
		exit(1); 
	}
	if (listen(fd,10) < 0) 
	{ 
		perror("listen failed"); 
		exit(1); 
	}
		memset(buffer,0,BUFSIZE);
		memset(sign,0,BUFSIZE);
		memset(ip_addr,0,BUFSIZE);
		memset(victim_ip_address,0,BUFSIZE);

		if((rqst = accept(fd, &victim_address, &victim_addr_len)) < 0) 
		{ 
			perror("accept failed"); exit(0); 
		}

		if((len = read(rqst, buffer, BUFSIZE)) < 0)
		{
			printf("Phase 3: Error in receiving data from tcp client");
			exit(0);
		}
		sscanf(buffer, "%s %s",sign, ip_addr);
		LOG(stdout, LOGL, "Received Message : %s %s",sign, ip_addr);
		sprintf(victim_ip_address, "%s", inet_ntoa(((struct sockaddr_in *)&victim_address)->sin_addr));
		LOG(stdout, LOGL, "victim ip %s",victim_ip_address);
		if(strncmp(sign, "startMarking", strlen(sign)) == 0)
		{
			LOG(stdout, LOGL, "Here");
			startMarking(object, ip_addr, victim_ip_address);
		}
	close(fd);
}

void listening_for_stopMark(struct command_line_args *object)
{
	int fd, rqst,len;
	struct sockaddr_in my_addr;
	struct sockaddr victim_address; 
	socklen_t victim_addr_len = sizeof(struct sockaddr);
	
	char buffer[BUFSIZE];

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{ 
		perror("cannot create socket"); 
		exit(0); 
	}

	memset((char*)&my_addr, 0, sizeof(struct sockaddr_in)); 
	my_addr.sin_family = AF_INET; 
	my_addr.sin_port = htons(object->tcpport+1); 

	my_addr.sin_addr.s_addr = inet_addr("0.0.0.0");

	if (bind(fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in)) < 0) 
	{
		perror("bind failed"); 
		exit(1); 
	}

	if (listen(fd,10) < 0) 
	{ 
		perror("listen failed"); 
		exit(1); 
	}


		memset(buffer,0,BUFSIZE);
		if((rqst = accept(fd, &victim_address, &victim_addr_len)) < 0) 
		{ 
			perror("accept failed"); exit(0); 
		}


		if((len = read(rqst, buffer, BUFSIZE)) < 0)
		{
			printf("Phase 3: Error in receiving data from tcp client");
			exit(0);
		}
		LOG(stdout, LOGL, "Received Message : %s",buffer);
		if(strncmp(buffer, "stopMarking", strlen(buffer)) == 0)
		{
			pthread_cancel(marker_thread);
		}
	close(fd);

}


int main(int argc, char **argv)
{

	struct command_line_args object;
	parse_command_line(argc, argv, &object);
	pthread_create(&marker_thread, 0, (void *)wait_for_startMarking, &object);
	pthread_create(&listener_for_stop, 0, (void *)listening_for_stopMark, &object);

	pthread_join(marker_thread, 0);
	pthread_join(listener_for_stop, 0);

	return 0;
}

