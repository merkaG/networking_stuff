/*
 * resolve.c
 * 
 * resolves an internet text address into (struct sockaddr_in).
 *
 * CHANGES: 1. added the RESOLVE_QUIET preprocessor conditions. Jan 1996
 *          2. added resolve_rns() to always provide both name/ip. March 1996
 */

#include <sys/types.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <netinet/in.h>
#include "resolve.h"

int resolve( const char *name, struct sockaddr_in *addr, int port )
     {
	struct hostent *host;
	
	/* clear everything in case I forget something */
	bzero(addr,sizeof(struct sockaddr_in));
	
	if (( host = gethostbyname(name) ) == NULL )  {
#ifndef RESOLVE_QUIET
	   fprintf(stderr,"unable to resolve host \"%s\" -- ",name);
	   perror("");
#endif
	   return -1;
	}
	 
	addr->sin_family = host->h_addrtype;
	memcpy((caddr_t)&addr->sin_addr,host->h_addr,host->h_length);
	addr->sin_port = htons(port);
     
        return 0;
     }

int resolve_rns( char *name , unsigned long addr )
     {
	struct hostent *host;
        unsigned long address;
	
	address = addr;
	host = gethostbyaddr((char *)&address,4,AF_INET);

      	if (!host)  {
#ifndef RESOLVE_QUIET
	   fprintf(stderr,"unable to resolve host \"%s\" -- ",inet_ntoa(addr));
	   perror("");
#endif

	   return -1;
	}


	strcpy(name,host->h_name);
	
        return 0;
     }
	

unsigned long addr_to_ulong(struct sockaddr_in *addr)
     {
	return addr->sin_addr.s_addr;
     }
