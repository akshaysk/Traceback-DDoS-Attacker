#include "traffana.h"
#include "log.h"

void parse_command_line(int argc, char **argv, struct command_line_args *ob)
{
	int opt = 0, longIndex = 0;
	memset(ob,'\0',sizeof(struct command_line_args));
	opt = getopt_long_only(argc, argv, ":vi:r:T:w:z:", longOpts, &longIndex);
	if(opt == -1)
		LOG(stderr, ERROR, "usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}] ");
	while (opt != -1)
	{
		switch(opt) 
		{
			case 'r':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]");
				ob->readFileName = optarg;
				break;		
			case 'w':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]");
				ob->writeFileName = optarg;
				break;		
			case 'i':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]");
				ob->interface = optarg;
				break;	
			case 'v':
				ob->verbose = 1;
				break;

			case 'T':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]");
				ob->timeEpoch = atof(optarg);
				break;				

			case 'z':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]");
				ob->tuple = atoi(optarg);
				if(!((ob->tuple == 2) || (ob->tuple == 5)))
					LOG(stderr, ERROR, "Invalid argument value for option -z");	
				break;

			case 'p':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]");
				ob->pktthresh = atoi(optarg);
				break;

			case 'b':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]");
				ob->bytethresh = atoi(optarg);
				break;
		
			case 'f':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]");
				ob->flowthresh = atoi(optarg);
				break;

			case 's':
				if(*optarg == '-')
					LOG(stderr, ERROR, "usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]");
				ob->srcthresh = atoi(optarg);
				break;

			case '?':
			case ':':
			default :
				LOG(stderr, ERROR, "usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]");

		}

	opt = getopt_long_only(argc, argv, "vi:r:T:w:z:", longOpts, &longIndex);
	}

	if(ob->pktthresh == 0)
		ob->pktthresh = INFINITY;	
	if(ob->bytethresh == 0)
		ob->bytethresh = INFINITY;	
	if(ob->flowthresh == 0)
		ob->flowthresh = INFINITY;	
	if(ob->srcthresh == 0)
		ob->srcthresh = INFINITY;	

	if(ob->timeEpoch == 0)
		ob->timeEpoch = 1;
	
	if(ob->tuple == 0)
		ob->tuple = 2;
	if(ob->writeFileName)
	{
		fp = fopen(ob->writeFileName,"w");
		if(!fp)
		{
			LOG(stderr, ERROR, "usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]");
		}
	}	
	else 
		fp = stdout;	
}

void print_op(struct command_line_args *object)
{
	if(object->verbose)
			LOG(fp, LOGL, "%lf %d %d %d %d %d %d %d %d %d", ref_time, total_count, total_bytes, no_of_flows, tcp_count, udp_count, icmp_count, others_count, tcp_flows, udp_flows);
	else
		LOG(fp, LOGL, "%lf %d %d %d", ref_time, total_count, total_bytes, no_of_flows); 
/*	struct flowLinkList *p = head;
	while(p!=NULL)
	{
		LOG(fp,LOGL,"%s->",p->address_string);
		p = p->next;
	}
	*/

	fflush(fp);
}

struct flowLinkList * create_node(char *mystring)
{
	struct flowLinkList * newNode = (struct flowLinkList *)malloc(sizeof(struct flowLinkList));
	if(!newNode)
	{
		LOG(stderr, ERROR, "Error in allocating new node");
	}
	newNode->address_string = (char *)malloc(strlen(mystring)+1);
	memset(newNode->address_string, '\0', strlen(mystring));
	strncpy(newNode->address_string, mystring, strlen(mystring));
	newNode->next = NULL;
	no_of_flows++;
	int len = strlen(mystring);
	if(mystring[len - 1] == 'g')
		tcp_flows++;
	else if(mystring[len - 1] == 'r')
		udp_flows++;
	return newNode;
	
}

void delete_list()
{
	struct flowLinkList *p = head;
	while(p!=NULL)
	{
		head = head->next;
		p->next = NULL;
		free(p);
		p = head;
	}
}

void delete_source_count_list()
{
	struct srcdestList *p = srcdestHead;
	while(p!=NULL)
	{
		srcdestHead = srcdestHead->next;
		p->next = NULL;
		free(p->srchead);
		free(p);
		p = srcdestHead;
	}
}

void append_to_flow_list(char *string, int tuple)
{
	int flag = 0;
	struct flowLinkList *p;	
	if(head == NULL)
	{
		head = create_node(string);
		return;
	}

	p = head;

	if(tuple == 2)
	{
		while(p!=NULL)
		{
			if(strncmp(p->address_string, string, strlen(string)-1) == 0)
			{
				flag = 1;	
				break;
			}
			p = p->next;
		}
	}

	else if(tuple == 5)
	{
		while(p!=NULL)
		{
			if(strncmp(p->address_string, string, strlen(string)) == 0)
			{
				flag = 1;	
				break;
			}
			p = p->next;
		}				
	}

	if(flag == 0)
	{
		p = create_node(string);
		p->next = head;
		head = p;
	}

}

struct srcdestList *create_sourcelist_node(char *src_ip_addr, char *dst_ip_addr, int src_len, int dst_len)
{
	struct srcdestList *newNode = (struct srcdestList *)malloc(sizeof(struct srcdestList));
	memset(newNode->dest_ip_addr,'\0',MAXIPADDRLEN);
	strncpy(newNode->dest_ip_addr, dst_ip_addr, dst_len); 
	newNode->srchead = (struct srclist *)malloc(sizeof(struct srclist));
	memset(newNode->srchead,'\0',sizeof(struct srclist));
	strncpy(newNode->srchead->src_ip_addr, src_ip_addr, src_len);
	newNode->srchead->next = NULL;
	newNode->no_of_sources = 1;
	newNode->next = NULL; 
	return newNode;
}

void maintain_src_counts(char *src_ip_addr, char *dst_ip_addr, int src_len, int dst_len)
{
	struct srcdestList *p;
	struct srclist *p_srclist, *new_srclist;
	if(srcdestHead == NULL)
	{
		srcdestHead = create_sourcelist_node(src_ip_addr, dst_ip_addr, src_len, dst_len);
	}

	else
	{
		p = srcdestHead;
		while(p != NULL)
		{
			if(strncmp(p->dest_ip_addr, dst_ip_addr, dst_len) == 0)
			{
				p_srclist = p->srchead;
				while(p_srclist != NULL)
				{
					if(strncmp(p_srclist->src_ip_addr, src_ip_addr, src_len) == 0)
					{
						goto end;
					}
					p_srclist = p_srclist->next;
				}
				if(p_srclist == NULL)
				{
					new_srclist = (struct srclist *)malloc(sizeof(struct srclist));
					memset(new_srclist, '\0', sizeof(struct srclist));
					strncpy(new_srclist->src_ip_addr, src_ip_addr, src_len);
					new_srclist->next = p->srchead;
					p->srchead = new_srclist;
					p->no_of_sources++;
					goto end;
				}
			}
			p = p->next;	
		}
		end:	
		if(p == NULL)
		{
			p = create_sourcelist_node(src_ip_addr, dst_ip_addr, src_len, dst_len);
			p->next = srcdestHead;
			srcdestHead = p;
		}
	}
	
}

int find_max_source_count()
{
	struct srcdestList *p = srcdestHead;
	int max_count = p->no_of_sources;
	while(p != NULL)
	{
		if(p->no_of_sources > max_count)
			max_count = p->no_of_sources;
	
		p = p->next;
	}	
	return max_count;
}

void send_attack_notification()
{

	struct sockaddr_in clientAddr,destAddr;
	int fd, port_no;
	char my_message[BUFSIZE], buffer[BUFSIZE];
	struct hostent *client_ip_addr, *dest_ip_addr;
	struct in_addr * address;
	memset(my_message,0,BUFSIZE);
	memset(buffer,0,BUFSIZE);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{ 
		perror("Phase 2: Error cannot create client server socket\n");
		exit(0);
	}
	memset((char *)&clientAddr, 0, sizeof(clientAddr)); 
	clientAddr.sin_family = AF_INET; 
	client_ip_addr = gethostbyname("localhost");
	address = (struct in_addr *)client_ip_addr->h_addr;

	clientAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*address));
	port_no = 62089;
	clientAddr.sin_port = htons(port_no);

	if(bind(fd, (struct sockaddr *)&clientAddr, sizeof(clientAddr)) < 0) 
	{ 
		perror("\nPhase 2: Client bind failed\n");
		exit(0);
	}

	memset((char *)&destAddr, 0, sizeof(destAddr)); 
	destAddr.sin_family = AF_INET; 
 	dest_ip_addr = gethostbyname("localhost");
	address = (struct in_addr *)dest_ip_addr->h_addr;

	destAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*address));
	
	destAddr.sin_port = htons(61089);

	snprintf(my_message,BUFSIZE,"Attack_Detected");	
	if(sendto(fd, my_message, strlen(my_message), 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0) 
		LOG(stderr, ERROR, "Error: Error in sendto() for traffana. Failed to send Attack Detected UDP message to endhost tool");

	LOG(stdout, LOGL, "Traffana: The Attack Detected message is successfully sent to endhost tool");

}
void count_flow(u_char *object, const struct sniff_ip *ip, const u_char *packet)
{
	const struct sniff_tcp *tcp;
	const struct sniff_udp *udp;
	u_short src_port_no = 0, dst_port_no = 0;
	struct in_addr src_addr, dst_addr;
	char *ip_string;
	int src_ip_len = 0, dst_ip_len = 0;
	int size_ip = 0;
	char src_ip_addr[MAXIPADDRLEN], dest_ip_addr[MAXIPADDRLEN];
	struct command_line_args *obj = (struct command_line_args *)object;
	size_ip = IP_HL(ip)*4;	
	if(ip->ip_p == 0x06 || ip->ip_p == 0x11)
	{
		ip_string = (char *)malloc(MAXLOGSIZE);
		memset(ip_string,'\0',MAXLOGSIZE);

		memcpy(&src_addr,&(ip->ip_src),sizeof(struct in_addr));
		memcpy(&dst_addr,&(ip->ip_dst),sizeof(struct in_addr));
		src_ip_len = strlen(inet_ntoa(src_addr));
		dst_ip_len = strlen(inet_ntoa(dst_addr));
		strncpy(ip_string,inet_ntoa(src_addr),src_ip_len);
		ip_string[src_ip_len] = ',';
		strncpy(ip_string+src_ip_len+1,inet_ntoa(dst_addr),dst_ip_len);
		ip_string[src_ip_len + dst_ip_len + 1] = ',';	
		if(((struct command_line_args *)object)->tuple == 2)
			sprintf(ip_string + src_ip_len + dst_ip_len + 2, "%c",'a'+ip->ip_p);

		else if(((struct command_line_args *)object)->tuple == 5)
		{
			if(ip->ip_p == 0x06)
			{
				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				src_port_no = ntohs(tcp->th_sport);
				dst_port_no = ntohs(tcp->th_dport);
				sprintf(ip_string + src_ip_len + dst_ip_len + 2, "%d,%d,%c", src_port_no, dst_port_no,'a'+ip->ip_p);
			}
			else if(ip->ip_p == 0x11)
			{
				udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
				src_port_no = ntohs(udp->th_sport);
				dst_port_no = ntohs(udp->th_dport);
				sprintf(ip_string + src_ip_len + dst_ip_len + 2, "%d,%d,%c", src_port_no, dst_port_no,'a'+ip->ip_p);
			}

		}
			
		append_to_flow_list(ip_string,((struct command_line_args *)object)->tuple);
		
		memset(src_ip_addr,'\0',MAXIPADDRLEN);
		memset(dest_ip_addr,'\0',MAXIPADDRLEN);
		strncpy(src_ip_addr, inet_ntoa(src_addr), MAXIPADDRLEN);
		strncpy(dest_ip_addr, inet_ntoa(dst_addr), MAXIPADDRLEN);
		maintain_src_counts(src_ip_addr, dest_ip_addr, src_ip_len, dst_ip_len);
		max_no_sources = find_max_source_count();
	}

	
	if(obj->pktthresh < total_count || obj->bytethresh < total_bytes || obj->flowthresh < no_of_flows || max_no_sources > obj->srcthresh)
	{
		char hostname[HOSTNAME];
		memset(hostname, 0, HOSTNAME);
		gethostname(hostname, sizeof(hostname));
		strcat(hostname, ".attackinfo");	
		fp_log = fopen(hostname, "w");
//		LOG(fp_log, LOGL, "Attack detected!!!");
		LOG(stdout, LOGL, "Attack Detected!!!");
		LOG(fp_log, LOGL, "%f %f %d %d %d",curtime, ref_time, total_count, total_bytes, no_of_flows);
		fflush(fp_log);
		send_attack_notification();
		exit(0);
	}
	
}


void read_packets(u_char *object, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{ 
	float delta = ((struct command_line_args *)object)->timeEpoch;
	const struct sniff_ip *ip;
	int version = 0;
	const struct sniff_tcp *tcp;
	int size_ip = 0, size_tcp = 0;

	curtime = (pkthdr->ts.tv_sec*1000000L + pkthdr->ts.tv_usec)/(double)1000000L;

	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	version = ip->ip_vhl >> 4;
	size_ip = IP_HL(ip)*4;	

	if(version != 4)
		return;
	if(size_ip < 20)
		return;

	if(ip->ip_p == 0x06)
	{
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) {
			return;
		}

	}

	if(ref_time == -1)
		ref_time = curtime;

	if(curtime - ref_time < delta)
	{
			total_bytes += pkthdr->len; 
			total_count++; 
			count_flow(object, ip, packet);
	}

	else if((curtime - ref_time) >= delta)
	{

		print_op((struct command_line_args *)object);
		no_of_flows = 0;
		tcp_flows = 0; udp_flows = 0;		
		total_count = 0;
		total_bytes = 0;
		tcp_count = 0;
		udp_count = 0;
		icmp_count = 0;
		others_count = 0;
		delete_list();
		delete_source_count_list();
		ref_time = ref_time + delta;
		if(curtime - ref_time > delta)
		{
			while(curtime - ref_time > delta)
			{
				print_op((struct command_line_args *)object);
				ref_time = ref_time + delta;
			}

		}
		total_bytes = pkthdr->len;
		total_count = 1;
		count_flow(object, ip, packet);
	}

	if(ip->ip_p == 0x01)
		icmp_count++;
	else if(ip->ip_p == 0x06)
		tcp_count++;
	else if(ip->ip_p == 0x11)
		udp_count++;
	else
		others_count++;


}

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct command_line_args object;
	parse_command_line(argc,argv,&object);	
		
	if(object.readFileName && object.interface)
	{
		LOG(stderr, ERROR, "Either interface or input should be specified");
	}
	
	if(object.readFileName)
	{
		if( (handle = pcap_open_offline(object.readFileName, errbuf)) == NULL)
		{
			LOG(stderr, ERROR, "Error opening dump file");
		}

	}

	else if(object.interface)
	{
		dev = object.interface;
		
		handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
		if (handle == NULL) {
			LOG(stderr, ERROR, "Couldn't open device %s: %s", dev, errbuf);
		}

	}
	else
	{
		LOG(stderr, ERROR, "No interface or input file is specified");
	}
	pcap_loop(handle, -1, read_packets, (u_char *)&object);

	print_op(&object);
	fclose(fp);
	return(0);
}
