#define _GNU_SOURCE
#include<stdio.h>
#include<dlfcn.h>
#include<stdlib.h>
#include<stdbool.h>
#include<string.h>
#include <openssl/ssl.h>

extern char * __progname;
static int (*hook_SSL_read)(SSL *ssl, void *buf, int num)= NULL;
static int (*hook_SSL_write)(SSL *ssl, const void *buf, int num)= NULL;

void PrintLog(bool read, void *buf)
{
	FILE *fp = NULL;
	if( fp = fopen("/tmp/file_log.txt", "a+") )
	{
		fprintf(fp, "%s : %s\n", read ? "[READ]" : "[WRITE]", buf);
		fclose(fp);
	}
}

int SSL_read(SSL *ssl, void *buf, int num)
{
	if (SSL_read == NULL)hook_SSL_read = dlsym(RTLD_NEXT, "SSL_read");
	PrintLog(true, buf);
	return hook_SSL_read(ssl, buf, num);
}

int SSL_write(SSL *ssl, const void *buf, int num)
{
	if (SSL_read == NULL)hook_SSL_read = dlsym(RTLD_NEXT, "SSL_write");
	PrintLog(false, buf);
	return hook_SSL_write(ssl, buf, num);
}


void __attribute__ ((constructor)) before_load(void)
{
	if (hook_SSL_read == NULL) hook_SSL_read 	= dlsym(RTLD_NEXT, "SSL_read");
	if (hook_SSL_write == NULL) hook_SSL_write 	= dlsym(RTLD_NEXT, "SSL_write");
}

