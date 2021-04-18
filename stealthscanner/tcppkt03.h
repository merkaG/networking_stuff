#ifndef TCPCKT03_H

unsigned short in_cksum(u_short *addr, int len);
int tcpip_send(int      socket,
	              struct sockaddr_in *address,
		      unsigned long s_addr,
		      unsigned long t_addr,
		      unsigned      s_port,
		      unsigned      t_port,
		      unsigned char tcpflags,
		      unsigned long seq,
		      unsigned long ack,
                      unsigned      win,
		      char          *datagram,
		      unsigned      datasize);
#endif
