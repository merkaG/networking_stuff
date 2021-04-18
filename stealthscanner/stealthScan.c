/*
 * scantcp.c
 * 
 * version 1.32 
 *  
 * Scans for listening TCP ports by sending packets to them and waiting for
 * replies. Relys upon the TCP specs and some TCP implementation bugs found 
 * when viewing tcpdump logs. 
 *
 * As always, portions recycled (eventually, with some stops) from n00k.c
 * (Wow, that little piece of code I wrote long ago still serves as the base
 *  interface for newer tools)
 * 
 * Technique:
 * 1. Active scanning: not supported - why bother.
 * 
 * 2. Half-open scanning:
 *      a. send SYN
 *      b. if reply is SYN|ACK send RST, port is listening
 *      c. if reply is RST, port is not listening
 * 
 * 3. Stealth scanning: (works on nearly all systems tested)
 *      a. sends FIN
 *      b. if RST is returned, not listening. 
 *      c. otherwise, port is probably listening.
 * 
 * (This bug in many TCP implementations is not limited to FIN only; in fact
 *  many other flag combinations will have similar effects. FIN alone was
 *  selected because always returns a plain RST when not listening, and the
 *  code here was fit to handle RSTs already so it took me like 2 minutes
 *  to add this scanning method)
 * 
 * 4. Stealth scanning: (may not work on all systems)
 *      a. sends ACK
 *      b. waits for RST
 *      c. if TTL is low or window is not 0, port is probably listening. 
 * 
 * (stealth scanning was created after I watched some tcpdump logs with
 *  these symptoms. The low-TTL implementation bug is currently believed
 *  to appear on Linux only, the non-zero window on ACK seems to exists on
 *  all BSDs.)
 * 
 * CHANGES:
 * --------
 * 0. (v1.0) 
 *    - First code, worked but was put aside since I didn't have time nor 
 *      need to continue developing it. 
 * 1. (v1.1)
 *    - BASE CODE MOSTLY REWRITTEN (the old code wasn't that maintainable)
 *    - Added code to actually enforce the usecond-delay without usleep()
 *      (replies might be lost if usleep()ing)
 * 2. (v1.2)
 *    - Added another stealth scanning method (FIN). 
 *      Tested and passed on:
 *      AIX 3
 *      AIX 4 
 *      IRIX 5.3 
 *      SunOS 4.1.3   
 *      System V 4.0 
 *      Linux 
 *      FreeBSD  
 *      Solaris
 *    
 *      Tested and failed on:
 *      Cisco router with services on ( IOS 11.0)
 *
 * 3. (v1.21) 
 *    - Code commented since I intend on abandoning this for a while.
 *
 * 4. (v1.3)
 *    - Resending for ports that weren't replied for.
 *      (took some modifications in the internal structures. this also
 *	 makes it possible to use non-linear port ranges 
 *	 (say 1-1024 and 6000))
 *
 * 5. (v1.31)
 *    - Flood detection - will slow up the sending rate if not replies are
 *	recieved for STCP_THRESHOLD consecutive sends. Saves alot of resends
 *	on easily-flooded networks.
 * 
 * 6. (v1.32)
 *      - Multiple port ranges support. 
 *        The format is: <start-end>|<num>[,<start-end>|<num>,...]
 *
 *        Examples: 20-26,113
 *                  20-100,113-150,6000,6660-6669
 * 		  
 * PLANNED: (when I have time for this)
 * ------------------------------------
 * (v2.x) - Multiple flag combination selections, smart algorithm to point
 *          out uncommon replies and cross-check them with another flag 
 *        
 */

#define RESOLVE_QUIET

#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "resolve.h"
#include "tcppkt03.h"

#define STCP_VERSION "1.32"
#define STCP_PORT  1234		/* Our local port. */
#define STCP_SENDS 3
#define STCP_THRESHOLD 8
#define STCP_SLOWFACTOR 10

/* GENERAL ROUTINES ------------------------------------------- */

void
banner (void)
{
  printf ("\nscantcp\n");
  printf ("version %s\n", STCP_VERSION);
}

void
usage (const char *progname)
{
  printf ("\nusage: \n");
  printf ("%s <method> <source> <dest> <ports> <udelay> <delay> [sf]\n\n",
	  progname);
  printf ("\t<method> : 0: half-open scanning (type 0, SYN)\n");
  printf ("\t           1: stealth scanning (type 1, FIN)\n");
  printf ("\t           2: stealth scanning (type 2, ACK)\n");
  printf ("\t<source> : source address (this host)\n");
  printf ("\t<dest>   : target to scan\n");
  printf ("\t<ports>  : ports/and or ranges to scan - eg: 21-30,113,6000\n");
  printf ("\t<udelay> : microseconds to wait between TCP sends\n");
  printf ("\t<delay>  : seconds to wait for TCP replies\n");
  printf
    ("\t[sf]     : slow-factor in case sends are dectected to be too fast\n\n");
}

/* OPTION PARSING etc ---------------------------------------- */

unsigned char *dest_name;
unsigned char *spoof_name;
struct sockaddr_in destaddr;

unsigned long dest_addr;
unsigned long spoof_addr;
unsigned long usecdelay;
unsigned waitdelay;

int slowfactor = STCP_SLOWFACTOR;

struct portrec			/* the port-data structure */
{
  unsigned n;
  int state;
  unsigned char ttl;
  unsigned short int window;
  unsigned long int seq;
  char sends;

} *ports;

char *portstr;

unsigned char scanflags;

int done;

int rawsock;			/* socket descriptors */
int tcpsock;

int lastidx = 0;		/* last sent index */
int maxports;			/* total number of ports */

void
timeout (int signum)		/* timeout handler           */
{				/* this is actually the data */
  int someopen = 0;		/* analyzer function. werd.  */
  unsigned lastsent;
  int checklowttl = 0;

  struct portrec *p;

  printf ("* SCANNING IS OVER\n\n");
  fflush (stdout);

  done = 1;


  for (lastsent = 0; lastsent < maxports; lastsent++)
    {
      p = ports + lastsent;
      if (p->state == -1)
	if (p->ttl > 64)
	  {
	    checklowttl = 1;
	    break;
	  }
    }

/* the above loop checks whether there's need to report low-ttl packets */

  for (lastsent = 0; lastsent < maxports; lastsent++)
    {
      p = ports + lastsent;

      destaddr.sin_port = htons (p->n);

      tcpip_send (rawsock, &destaddr,
		  spoof_addr, destaddr.sin_addr.s_addr,
		  STCP_PORT, ntohs (destaddr.sin_port),
		  TH_RST, p->seq++, 0, 512, NULL, 0);
    }				/* just RST -everything- sent   */
  /* this inclued packets a reply */
  /* (even RST) was recieved for  */




  for (lastsent = 0; lastsent < maxports; lastsent++)
    {				/* here is the data analyzer */
      p = ports + lastsent;
      switch (scanflags)
	{
	case TH_SYN:
	  switch (p->state)
	    {
	    case -1:
	      break;
	    case 1:
	      printf ("# port %d is listening.\n", p->n);
	      someopen++;
	      break;
	    case 2:
	      printf ("# port %d maybe listening (unknown response).\n",
		      p->n);
	      someopen++;
	      break;
	    default:
	      printf ("# port %d needs to be rescanned.\n", p->n);
	    }
	  break;
	case TH_ACK:
	  switch (p->state)
	    {
	    case -1:
	      if (((p->ttl < 65) && checklowttl) || (p->window > 0))
		{
		  printf ("# port %d maybe listening", p->n);
		  if (p->ttl < 65)
		    printf (" (low ttl)");
		  if (p->window > 0)
		    printf (" (big window)");
		  printf (".\n");
		  someopen++;
		}
	      break;
	    case 1:
	    case 2:
	      printf ("# port %d has an unexpected response.\n", p->n);
	      break;
	    default:
	      printf ("# port %d needs to be rescanned.\n", p->n);
	    }
	  break;
	case TH_FIN:
	  switch (p->state)
	    {
	    case -1:
	      break;
	    case 0:
	      printf ("# port %d maybe open.\n", p->n);
	      someopen++;
	      break;
	    default:
	      printf ("# port %d has an unexpected response.\n", p->n);
	    }
	}
    }

  printf ("-----------------------------------------------\n");
  printf ("# total ports open or maybe open: %d\n\n", someopen);
  free (ports);

  exit (0);			/* heh. */

}


int
resolve_one (const char *name, unsigned long *addr, const char *desc)
{
  struct sockaddr_in tempaddr;
  if (resolve (name, &tempaddr, 0) == -1)
    {
      printf ("error: can't resolve the %s.\n", desc);
      return -1;
    }

  *addr = tempaddr.sin_addr.s_addr;
  return 0;
}

void
give_info (void)
{
  printf ("# response address           : %s (%s)\n", spoof_name,
	  inet_ntoa (spoof_addr));
  printf ("# target address             : %s (%s)\n", dest_name,
	  inet_ntoa (dest_addr));
  printf ("# ports                      : %s\n", portstr);
  printf ("# (total number of ports)    : %d\n", maxports);
  printf ("# delay between sends        : %lu microseconds\n", usecdelay);
  printf ("# delay                      : %u seconds\n", waitdelay);
  printf ("# flood dectection threshold : %d unanswered sends\n",
	  STCP_THRESHOLD);
  printf ("# slow factor                : %d\n", slowfactor);
  printf ("# max sends per port         : %d\n\n", STCP_SENDS);
}


int
parse_args (int argc, char *argv[])
{

  if (strrchr (argv[0], '/') != NULL)
    argv[0] = strrchr (argv[0], '/') + 1;

  if (argc < 7)
    {
      printf ("%s: not enough arguments\n", argv[0]);
      return -1;
    }

  switch (atoi (argv[1]))
    {
    case 0:
      scanflags = TH_SYN;
      break;
    case 1:
      scanflags = TH_FIN;
      break;
    case 2:
      scanflags = TH_ACK;
      break;
    default:
      printf ("%s: unknown scanning method\n", argv[0]);
      return -1;
    }

  spoof_name = argv[2];
  dest_name = argv[3];

  portstr = argv[4];

  usecdelay = atol (argv[5]);
  waitdelay = atoi (argv[6]);

  if (argc > 7)
    slowfactor = atoi (argv[7]);

  if ((usecdelay == 0) && (slowfactor > 0))
    {
      printf ("%s: adjusting microsecond-delay to 1usec.\n");
      usecdelay++;
    }
  return 0;
}

/* MAIN ------------------------------------------------------ */

int
build_ports (char *str)		/* build the initial port-database */
{
  int i;
  int n;
  struct portrec *p;
  int sport;

  char *s;


  s = str;
  maxports = 0;
  n = 0;

  while (*s != '\0')
    {
      switch (*s)
	{
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	  n *= 10;
	  n += (*s - '0');
	  break;
	case '-':
	  if (n == 0)
	    return -1;
	  sport = n;
	  n = 0;
	  break;
	case ',':
	  if (n == 0)
	    return -1;
	  if (sport != 0)
	    {
	      if (sport >= n)
		return -1;
	      maxports += n - sport;
	      sport = 0;
	    }
	  else
	    maxports++;
	  n = 0;
	  break;
	}
      s++;
    }
  if (n == 0)
    return -1;
  if (sport != 0)
    {
      if (sport >= n)
	return -1;
      maxports += n - sport;
      sport = 0;
    }
  else
    maxports++;

  maxports += 2;

  if ((ports =
       (struct portrec *) malloc ((maxports) * sizeof (struct portrec))) ==
      NULL)
    {
      fprintf (stderr, "\nerror: not enough memory for port database\n\n");
      exit (1);
    }

  s = str;
  maxports = 0;
  n = 0;

  while (*s != '\0')
    {
      switch (*s)
	{
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	  n *= 10;
	  n += (*s - '0');
	  break;
	case '-':
	  if (n == 0)
	    return -1;
	  sport = n;
	  n = 0;
	  break;
	case ',':
	  if (n == 0)
	    return -1;
	  if (sport != 0)
	    {
	      if (sport >= n)
		return -1;
	      while (sport <= n)
		{
		  for (i = 0; i < maxports; i++)
		    if ((ports + i)->n == sport)
		      break;

		  if (i < maxports - 1)
		    printf ("notice: duplicate port - %d\n", sport);
		  else
		    {
		      (ports + maxports)->n = sport;
		      maxports++;
		    }
		  sport++;
		}
	      sport = 0;
	    }
	  else
	    {
	      for (i = 0; i < maxports; i++)
		if ((ports + i)->n == n)
		  break;

	      if (i < maxports - 1)
		printf ("notice: duplicate port - %d\n", n);
	      else
		{
		  (ports + maxports)->n = n;
		  maxports++;
		}
	    }
	  n = 0;
	  break;
	}
      s++;
    }


  if (n == 0)
    return -1;
  if (sport != 0)
    {
      if (sport >= n)
	return -1;
      while (sport <= n)
	{
	  for (i = 0; i < maxports; i++)
	    if ((ports + i)->n == sport)
	      break;

	  if (i < maxports - 1)
	    printf ("notice: duplicate port - %d\n", sport);
	  else
	    {
	      (ports + maxports)->n = sport;
	      maxports++;
	    }
	  sport++;
	}
      sport = 0;
    }
  else
    {
      for (i = 0; i < maxports; i++)
	if ((ports + i)->n == n)
	  break;

      if (i < maxports - 1)
	printf ("notice: duplicate port - %d\n", n);
      else
	{
	  (ports + maxports)->n = n;
	  maxports++;
	}
    }

  printf ("\n");

  for (i = 0; i < maxports; i++)
    {
      p = ports + i;
      p->state = 0;
      p->sends = 0;
    }

  return 0;

}

struct portrec *
portbynum (int num)
{
  int i = 0;

  while (((ports + i)->n != num) && (i < maxports))
    i++;

  if (i == maxports)
    return NULL;

  return (ports + i);
}

struct portrec *
nextport (char save)
{
  struct portrec *p = ports;
  int doneports = 0;

  int oldlastidx = lastidx;

  while (doneports != maxports)
    {
      p = ports + lastidx;

      if ((p->state != 0) || (p->sends == STCP_SENDS))
	{
	  doneports++;
	  lastidx++;
	  lastidx %= maxports;
	}
      else
	break;
    }

  if (save)
    lastidx = oldlastidx;
  else
    lastidx = (lastidx + 1) % maxports;

  if (doneports == maxports)
    return NULL;

  return p;
}




unsigned long
usecdiff (struct timeval *a, struct timeval *b)
{
  unsigned long s;

  s = b->tv_sec - a->tv_sec;
  s *= 1000000;
  s += b->tv_usec - a->tv_usec;

  return s;			/* return the stupid microsecond diff */
}

void
main (int argc, char *argv[])
{
  int lastsent = 0;

  char buf[3000];

  struct iphdr *ip = (struct iphdr *) (buf);
  struct tcphdr *tcp = (struct tcphdr *) (buf + sizeof (struct iphdr));

  struct sockaddr_in from;
  int fromlen;

  struct portrec *readport;

  fd_set rset, wset;

  struct timeval waitsend, now, del;

  unsigned long udiff;

  int sendthreshold = 0;


  banner ();

  if (parse_args (argc, argv))
    {
      usage (argv[0]);
      return;
    }

  if (resolve_one (dest_name, &dest_addr, "destination host"))
    exit (1);

  destaddr.sin_addr.s_addr = dest_addr;
  destaddr.sin_family = AF_INET;

  if (resolve_one (spoof_name, &spoof_addr, "source host"))
    exit (1);

  if (build_ports (portstr) == -1)
    {
      printf ("\n%s: bad port string\n", argv[0]);
      usage (argv[0]);
      return;
    }

  //give_info();

  if ((tcpsock = socket (AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
      printf ("\nerror: %s\n\n", strerror (errno));
      exit (1);
    }
  if ((rawsock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
    {
      printf ("\nerror: couldn't get raw socket\n\n");
      exit (1);
    }

  /* well, let's get to it. */

  done = 0;

  printf ("* BEGINNING SCAN\n");
  fflush (stdout);

  gettimeofday (&waitsend, NULL);

  while (!done)
    {

      if (nextport (1) == NULL)
	{
	  alarm (0);		/* no more sends, now we just  */
	  signal (SIGALRM, timeout);	/* to wait <waitdelay> seconds */
	  alarm (waitdelay);	/* before resetting and giving */
	}			/* results.                    */

      FD_ZERO (&rset);

      FD_SET (tcpsock, &rset);

      gettimeofday (&now, NULL);

      udiff = usecdiff (&waitsend, &now);

      /* here comes the multiple choice select().
       * well, there are 3 states: 
       * 1. already sent all the packets.
       * 2. didn't send all the packets, but it's not time for another send
       * 3. didn't send all the packets and it is time for another send.
       */

      if (nextport (1) != NULL)
	if (udiff > usecdelay)
	  {
	    FD_ZERO (&wset);
	    FD_SET (rawsock, &wset);
	    select (FD_SETSIZE, &rset, &wset, NULL, NULL);
	  }
	else
	  {
	    del.tv_sec = 0;
	    del.tv_usec = usecdelay;
	    select (FD_SETSIZE, &rset, NULL, NULL, &del);
	  }
      else
	select (FD_SETSIZE, &rset, NULL, NULL, NULL);

      if (FD_ISSET (tcpsock, &rset))	/* process the reply */
	{
	  fromlen = sizeof (from);

	  recvfrom (tcpsock, &buf, 3000, 0,
		    (struct sockaddr *) &from, &fromlen);

	  if (from.sin_addr.s_addr == destaddr.sin_addr.s_addr)
	    if (ntohs (tcp->th_dport) == STCP_PORT)
	      {
		printf ("* got reply");

		readport = portbynum (ntohs (tcp->th_sport));

		if (readport == NULL)
		  printf (" -- bad port");
		else
		  {
		    sendthreshold = 0;
		    if (!readport->state)
		      {
			readport->ttl = ip->ttl;
			readport->window = tcp->th_win;

			if (tcp->th_flags & TH_RST)
			  {
			    readport->state = -1;
			    printf (" (RST)");
			    if (readport->ttl < 65)
			      printf (" (short ttl)");
			    if (readport->window > 0)
			      printf (" (big window)");
			  }
			else if (tcp->th_flags & (TH_ACK | TH_SYN))
			  {
			    readport->state = 1;
			    printf (" (SYN+ACK)");
			    tcpip_send (rawsock, &destaddr,
					spoof_addr, destaddr.sin_addr.s_addr,
					STCP_PORT, readport->n,
					TH_RST,
					readport->seq++, 0, 512, NULL, 0);
			  }
			else
			  {
			    readport->state = 2;
			    printf (" (UNEXPECTED)");
			    tcpip_send (rawsock, &destaddr,
					spoof_addr, destaddr.sin_addr.s_addr,
					STCP_PORT, readport->n,
					TH_RST,
					readport->seq++, 0, 512, NULL, 0);
			  }
		      }
		    else
		      printf (" (duplicate)");
		  }
		printf ("\n");
		fflush (stdout);
	      }
	}

      if (nextport (1) != NULL)
	if (FD_ISSET (rawsock, &wset))	/* process the sends */
	  {
	    readport = nextport (0);

	    destaddr.sin_port = htons (readport->n);

	    printf ("* sending to port %d ", ntohs (destaddr.sin_port));

	    readport->seq = lrand48 ();
	    readport->sends++;

	    tcpip_send (rawsock, &destaddr,
			spoof_addr, destaddr.sin_addr.s_addr,
			STCP_PORT, ntohs (destaddr.sin_port),
			scanflags, readport->seq++, lrand48 (), 512, NULL, 0);

	    gettimeofday (&waitsend, NULL);

	    FD_ZERO (&wset);

	    printf ("\n");

	    if ((++sendthreshold > STCP_THRESHOLD) && (slowfactor))
	      {
		printf ("\n\n -- THRESHOLD CROSSED - SLOWING UP SENDS\n\n");
		usecdelay *= slowfactor;
		sendthreshold = 0;
	      }
	  }
    }
}
