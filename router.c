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

	if(ob->routerfile == NULL || ob->tcpport == 0 || ob->udpport == 0 || ob->stopthresh == 0)
		LOG(stderr, ERROR, "usage: router [-e epoch] [-t port] [-u por] [-p prob] \n");

}

void wait_for_startMarking(struct command_line_args *object)
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
	my_addr.sin_port = htons(object->tcpport); 
	router_ip_addr = gethostbyname("localhost");
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

	}	
}


int main(int argc, char **argv)
{

	struct command_line_args object;

	parse_command_line(argc, argv, &object);

	wait_for_startMarking(&object);

	return 0;
}

