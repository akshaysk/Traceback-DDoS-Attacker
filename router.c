#include "router.h"
#include "log.h"
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


void delete_thread_list()
{
	struct thread_list *p = thread_list_head;
	while(p != NULL)
	{
		thread_list_head = thread_list_head->next;
		p->next = NULL;
		free(p);
		p = thread_list_head;
	}

}

void kill_rest_of_threads(int thread_id)
{

	struct thread_list *p = thread_list_head;
	while(p!=NULL)
	{
		if(p->thread_id != thread_id)
		{
			pthread_cancel(p->thread);
		}
		p = p->next;
	}
	delete_thread_list();

}

void startMarking()
{


}

void wait_for_startMarking(struct ip_tcp_port *object)
{
	int fd, rqst,len;
	struct hostent *router_ip_addr;
	struct in_addr * address;
	struct sockaddr_in my_addr; 
	socklen_t alen = sizeof(my_addr);
	char buffer[BUFSIZE];

	memset(buffer,0,BUFSIZE);
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{ 
		perror("cannot create socket"); 
		exit(0); 
	}

	memset((char*)&my_addr, 0, sizeof(my_addr)); 
	my_addr.sin_family = AF_INET; 
	my_addr.sin_port = htons(object->tcp_port); 
	router_ip_addr = gethostbyname(object->ip_addr);
	address = (struct in_addr *)router_ip_addr->h_addr;

	my_addr.sin_addr.s_addr = inet_addr(inet_ntoa(*address));
	
	if (bind(fd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0) 
	{
		perror("bind failed"); 
		exit(1); 
	}
	
	if (listen(fd,10) < 0) 
	{ 
		perror("listen failed"); 
		exit(1); 
	}

	if((rqst = accept(fd, (struct sockaddr *)NULL, &alen)) < 0) 
	{ 
		perror("accept failed"); exit(0); 
	}


	if((len = read(rqst, buffer, BUFSIZE)) < 0)
	{
		printf("Phase 3: Error in receiving data from tcp client");
		exit(0);
	}
	if(strncmp(buffer, "startMarking", sizeof(buffer)) == 0)
	{
		kill_rest_of_threads(object->thread_id);
		startMarking();
	}	
}

struct thread_list * create_node(int thread_id, int tcpport, char *ip_addr)
{
	struct thread_list * newNode = (struct thread_list *)malloc(sizeof(struct thread_list));
	if(!newNode)
	{
		LOG(stderr, ERROR, "Error in allocating new node");
	}
	newNode->thread_id = thread_id;
	newNode->next = NULL;
		
	struct ip_tcp_port ip_tcp_object;
	memset((char *)&ip_tcp_object, '\0', sizeof(struct ip_tcp_port));
	ip_tcp_object.tcp_port = tcpport; 
	ip_tcp_object.ip_addr = ip_addr;		
	ip_tcp_object.thread_id = thread_id;
	pthread_create(&newNode->thread, 0, (void *)wait_for_startMarking, &ip_tcp_object);
	return newNode;
	
}

void append_to_thread_list(int thread_id, int tcpport, char *ip_addr)
{
	struct thread_list *p;	
	if(thread_list_head == NULL)
	{
		thread_list_head = create_node(thread_id, tcpport, ip_addr);
		return;
	}
	else
	{
		p = create_node(thread_id, tcpport, ip_addr);
		p->next = thread_list_head;
		thread_list_head = p;
	}
}

void schedule_threads_to_listen(struct command_line_args *object)
{

	pcap_if_t *alldevs, *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_addr_t *p;
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	for(d=alldevs; d; d=d->next)
	{
		if (d->addresses)
		{
			p = d->addresses;
			while(p != NULL)
			{
				if(p->addr->sa_family == AF_INET)
				{
	
					no_of_threads++;
					append_to_thread_list(no_of_threads, object->tcpport, inet_ntoa(((struct sockaddr_in *)p->addr)->sin_addr));
					
				}
				p = p->next;
			}
			printf("\n");
		}
	}

}


/*void read_packets(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{ 
	const struct sniff_ip *ip;
	int version = 0;
	int size_ip = 0, size_udp = 0;
	char *payload;
	char ip_addr[MAXIPADDRLEN];
	memset(ip_addr, '\0', sizeof(ip_addr));
	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	version = ip->ip_vhl >> 4;
	size_ip = IP_HL(ip)*4;	
	LOG(stdout, LOGL, "%d\t%d",version, size_ip);
	if(version != 4)
		return;
	if(size_ip < 20)
		return;
	LOG(stdout, LOGL, "stage1");
	if(ip->ip_p == 0x11)
	{
		LOG(stdout, LOGL, "stage2");
		size_udp = sizeof(struct sniff_udp);
		payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_udp);	
		if(strstr(payload, "YOURIP"))
		{
			strncpy(ip_addr, payload+7,MAXIPADDRLEN);
			LOG(stdout, LOGL, "Received message from endhost: IP address is %s",ip_addr);
			exit(0);
		}
	}


}
void sniff_packets_for_signature_packet()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live("wlan0", BUFSIZ, 1, 0, errbuf);
	if (handle == NULL) {
		LOG(stderr, ERROR, "Couldn't open device");
	}

	pcap_loop(handle, -1, read_packets, NULL);
}



void check_for_signature_packet_from_endhost(char *router_ip)
{
	int count = 0;
	int fd,len;
	struct sockaddr_in myAddr, srcAddr;
	struct hostent *my_ip_addr;
	struct in_addr *address;
	char buffer[BUFSIZE];
//	extern int file_server_exists;

	socklen_t addrlen = sizeof(srcAddr);

	memset(buffer,'\0',BUFSIZE);
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{ 
		LOG(stderr, ERROR, "Error: Cannot create socket of directory server");
	}

	memset((char *)&myAddr, 0, sizeof(myAddr)); 
	myAddr.sin_family = AF_INET; 
	
	my_ip_addr = gethostbyname(router_ip);
	address = (struct in_addr *)my_ip_addr->h_addr;

	myAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*address));
	
	myAddr.sin_port = htons(59089);
	if (bind(fd, (struct sockaddr *)&myAddr, sizeof(myAddr)) < 0) 
	{ 
		LOG(stderr, ERROR, "Error: EndHost tool bind failed");
	}
	LOG(stdout, LOGL, "stage1 %d",count++);

	while((len = recvfrom(fd, buffer, BUFSIZE, 0, (struct sockaddr *)&srcAddr, &addrlen))<0)
	{
		LOG(stderr, ERROR, "Error in receiving registration data");
		continue;
	}
	
	LOG(stdout, LOGL, "Router: Router tool has received message: %s",buffer);

}
*/

int main(int argc, char **argv)
{

	struct command_line_args object;
	parse_command_line(argc, argv, &object);
//	start_listening_on_all_ports_for_signature();
	schedule_threads_to_listen(&object);
//	sniff_packets_for_signature_packet();
//	check_for_signature_packet_from_endhost("localhost");
//	check_for_signature_packet_from_endhost("192.168.1.10");
//	pthread_create(&thr1, 0, (void *)check_for_signature_packet_from_endhost, "localhost");
//	pthread_create(&thr2, 0, (void *)check_for_signature_packet_from_endhost, "192.168.1.10");
//	pthread_join(thr1,0);
//	pthread_join(thr2,0);	
	return 0;
}

