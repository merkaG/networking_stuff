#ifndef RESOLVE_H

unsigned long addr_to_ulong(struct sockaddr_in *addr);
int resolve( const char *name, struct sockaddr_in *addr, int port);

#endif
