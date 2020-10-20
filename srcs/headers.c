#include "../includes/ft_nmap.h"

void    gentcphdr(struct tcphdr *tcph, int port, uint8_t flag)
{
    tcph->source = htons(port);
	tcph->dest = htons(port);
	tcph->seq = htonl(port);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->fin= (flag & T_FIN) ? 1 : 0;
	tcph->syn= (flag & T_SYN) ? 1 : 0;
	tcph->rst= (flag & T_RST) ? 1 : 0;
	tcph->psh= (flag & T_PUSH) ? 1 : 0;
	tcph->ack= (flag & T_ACK) ? 1 : 0;
	tcph->urg= (flag & T_URG) ? 1 : 0;
	tcph->window = htons(14600);
	tcph->check = 0; 
	tcph->urg_ptr = 0;
    tcph->dest = htons(port);
	tcph->check = 0;
}

void	geniphdr(struct ip *ip, char *addr)
{
	struct in_addr ad;

	inet_pton(AF_INET, addr, &ad);
	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_tos = 0;
	ip->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
	ip->ip_off = 0;
	ip->ip_ttl = 255;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_sum = 0;
	ip->ip_id = htons(5);
	ip->ip_dst = ad;
}

uint16_t    genpshdr(struct tcphdr *tcph, uint32_t s_addr, char *local)
{
    t_psh       psh;
    uint16_t    ret;

    psh.source_address = inet_addr(local);
	psh.dest_address = s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));
	ft_memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
    ret = csum((unsigned short*)&psh, sizeof(t_psh));
    return ret;
}