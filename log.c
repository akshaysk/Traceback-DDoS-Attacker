#include "log.h" 
void LOG(FILE *fp,int LOG_LEVEL, char *format,...)
{
	va_list arguments;
	char message[MAXLOGSIZE];
	int msgsize;
	va_start(arguments,format);
	msgsize = vsnprintf(message,sizeof(message),format,arguments);
	va_end(arguments);
	if(msgsize < 0)
		return;
	fprintf(fp,"\n%s",message);
	fflush(fp);
	if(LOG_LEVEL == ERROR)
		exit(0);

}

