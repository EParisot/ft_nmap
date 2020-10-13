#include "../includes/ft_nmap.h"

typedef struct s_psh
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
    struct tcphdr tcp;
}               t_psh;

static void fin_iphdr(t_opt *opt, struct iphdr* iph, char *datagram, struct in_addr dest_ip)
{
    iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id = htons(0);
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(opt->localhost);
	iph->daddr = dest_ip.s_addr;
    iph->check = csum((unsigned short *) datagram, iph->tot_len >> 1);
}

static void fin_tcphdr(struct tcphdr* tcph)
{
    tcph->source = htons(9999);
	tcph->dest = htons(80);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->fin=1;
	tcph->syn=0;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons(14600);
	tcph->check = 0; 
	tcph->urg_ptr = 0;
}

static struct sockaddr_in probe_fillfinpacket(t_opt *opt, int sock, char **pkt, char *addr, int port)
{

	char *datagram = *pkt;	
    int one = 1;
	const int *val = &one;
    struct tcphdr   *tcph;
	struct sockaddr_in  dest;
    struct in_addr dest_ip;
    t_psh   psh;

    tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
    dest_ip.s_addr = inet_addr(addr);
    ft_memset(datagram, 0, 4096);
    fin_iphdr(opt, (struct iphdr *)datagram, datagram, dest_ip);
    fin_tcphdr((struct tcphdr *)(datagram + sizeof(struct ip)));
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		printf ("Error setting IP_HDRINCL. \n");
	}
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;
    tcph->dest = htons(port);
	tcph->check = 0;	
    psh.source_address = inet_addr(opt->localhost);
	psh.dest_address = dest.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));
	ft_memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
	tcph->check = csum((unsigned short*)&psh, sizeof(t_psh));
    return dest;
}

int scan_fin(t_opt *opt, int sock, char *addr, int port)
{
    int ret;
	unsigned short hl;
    struct timeval tv;
    char    pkt[4096];
	char	rcpkt[4096];
    char *tmp = pkt;
    struct sockaddr_in dest;

    ret = -1;
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
    dest = probe_fillfinpacket(opt, sock, &tmp, addr, port);
    if (sendto(sock, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
	{
		printf ("Error sending fin packet.\n");
		return -1;
	}
	ft_bzero(&rcpkt, sizeof(rcpkt));
	if ((ret = recvfrom(sock, rcpkt, sizeof(rcpkt), 0, NULL, NULL)) > 0)
	{
		struct iphdr* iph = (struct iphdr*)rcpkt;
		hl = iph->ihl * 4;
		struct tcphdr *tcp = (struct tcphdr*)(rcpkt + hl);
		if (tcp->th_flags & 0x04)
			printf("FIN port %d is closed\n", port);
		else
			printf("FIN port %d is maybe filtered\n", port);
		// missing icmp errr to mark as filtered
	}
	else
		printf("FIN port %d is open|filtered\n", port);
    return ret;
}