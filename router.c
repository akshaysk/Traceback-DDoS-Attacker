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

int main(int argc, char **argv)
{

	struct command_line_args object;

	parse_command_line(argc, argv, &object);


	return 0;
}

