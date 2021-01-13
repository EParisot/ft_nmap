#include "../includes/ft_nmap.h"

int scantcp(t_opt *opt, int32_t sock, uint8_t *addr, int32_t port, uint8_t flag, int z) // a restructurer pour avoir 4 args only
{
    struct timeval      tv;
    char                pkt[4096];
    struct sockaddr_in  dest;
    char                *datagram = pkt;	
    int32_t             one = 1;
	const int32_t       *val = &one;
	ft_bzero(&dest, sizeof(struct sockaddr_in));
    ft_memset(datagram, 0, 4096);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv)) < 0)
    {
        printf("ft_nmap: timeout sending probe\n");
        return -1;
    }
    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0)
    {
        printf("ft_nmap: timeout recv probe\n");
        return -1;
    }
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		printf ("Error setting IP_HDRINCL. \n");
        return -1;
	}
	geniphdr((struct ip *)datagram, addr, IPPROTO_TCP, sizeof(struct ip) + sizeof(struct tcphdr));
    gentcphdr((struct tcphdr *)(datagram + sizeof(struct ip)), port, flag);
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = inet_addr((char*)addr);
	((struct tcphdr *)(datagram + sizeof(struct ip)))->check = genpshdr((struct tcphdr *)(datagram + sizeof(struct ip)), inet_addr((char*)addr), opt->localhost);
    while (z--)
    {
        if (sendto(sock, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0)
    	{
	    	printf ("Error sending tcp packet.\n");
	    	return -1;
	    }
    }
	return (0);
}

int scanudp(t_opt *opt, int sock, char *addr, int port)
{
    struct timeval tv;
    char    pkt[4096];
    char *datagram = pkt;
    struct sockaddr_in dest;

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv)) < 0)
    {
        printf("ft_nmap: timeout sending probe\n");
        return -1;
    }
    ft_memset(datagram, 0, 4096);
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(addr);
    geniphdr((struct ip*)datagram, (uint8_t*)addr, IPPROTO_UDP, sizeof (struct iphdr) + sizeof (struct udphdr));
    genudphdr(&datagram, port, addr, (char*)opt->localhost);
    int z = 2;
    while (z--)
    {
    if (sendto(sock, pkt, 42, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        printf ("Error sending udp packet.\n");
        return -1;
    }
    }
    //pthread_mutex_unlock(opt->lock);
    return 1;
}