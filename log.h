#ifndef _LOG_H_
#define _LOG_H_
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#define MAXLOGSIZE	256
#define ERROR	0
#define LOGL	1
void LOG(FILE *fp,int LOG_LEVEL, char *format,...);
#endif
