#include "../includes/ft_nmap.h"

static void syn_tcphdr(struct tcphdr* tcph, int port)
{
    tcph->source = htons(port);
	tcph->dest = htons(port);
	tcph->seq = htonl(port);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons(14600);
	tcph->check = 0; 
	tcph->urg_ptr = 0;
}

static struct sockaddr_in probe_fillsynpacket(t_opt *opt, int sock, char **pkt, char *addr, int port)
{

	char *datagram = *pkt;	
    int one = 1;
	const int *val = &one;
    struct tcphdr   *tcph;
	struct sockaddr_in  dest;
    t_psh   psh;

	ft_bzero(&dest, sizeof(struct sockaddr_in));
    tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
    ft_memset(datagram, 0, 4096);
    geniphdr((struct ip *)datagram, addr);
    syn_tcphdr((struct tcphdr *)(datagram + sizeof(struct ip)), port);
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		printf ("Error setting IP_HDRINCL. \n");
	}
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = inet_addr(addr);
    tcph->dest = htons(port);
	tcph->check = 0;
    psh.source_address = inet_addr(opt->localhost);
	psh.dest_address = dest.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));
	ft_memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
	tcph->check = csum((unsigned short*)&psh, sizeof(t_psh));
    return (dest);
}

int scan_syn(t_opt *opt, int sock, char *addr, int port)
{
    struct timeval tv;
    char    pkt[4096];
    char *tmp = pkt;
    struct sockaddr_in dest;

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv)) < 0)
    {
        printf("ft_nmap: timeout sending probe\n");
        return -1;
    }
	dest = probe_fillsynpacket(opt, sock, &tmp, addr, port);
	if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0)
    {
        printf("ft_nmap: timeout recv probe\n");
        return -1;
    }
    if (sendto(sock, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0)
	{
		printf ("Error sending syn packet.\n");
		return -1;
	}
	return (0);
}