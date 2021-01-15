#include "../includes/ft_nmap.h"

void    gentcphdr(struct tcphdr *tcph, int32_t port, uint8_t flag, int32_t dst)
{
    tcph->source = htons(dst);
	tcph->dest = htons(port);
	tcph->seq = htons(port);
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
}

void	geniphdr(struct ip *ip, uint8_t *addr, int protocol, int tot_len)
{
	struct in_addr ad;

	inet_pton(AF_INET, (char*)addr, &ad);
	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_tos = 0;
	ip->ip_len = tot_len;
	ip->ip_off = 0;
	ip->ip_ttl = 50;
	ip->ip_p = protocol;
	ip->ip_sum = 0;
	ip->ip_id = htons(1);
	ip->ip_dst = ad;
}

uint16_t    genpshdr(struct tcphdr *tcph, uint32_t s_addr, uint8_t *local)
{
    t_psh       psh;
    uint16_t    ret;

    psh.source_address = inet_addr((char*)local);
	psh.dest_address = s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));
	ft_memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
    ret = csum((unsigned short*)&psh, sizeof(t_psh));
    return ret;
}

void	genudphdr(char **pkt, int port, char *addr, char *host, int32_t dst)
{
	char *datagram = *pkt;
	struct udphdr*	udph = (struct udphdr *) (datagram + sizeof (struct ip));
	t_udppsh   psh;
	char *pseudogram;

	udph->source = htons(dst);
    udph->dest = htons(port);
    udph->len = htons(sizeof(struct udphdr));
    udph->check = 0;

	psh.source_address = inet_addr(host);
    psh.dest_address = inet_addr(addr);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr));
    
    pseudogram = malloc(sizeof(t_udppsh) + sizeof(struct udphdr));
    memcpy(pseudogram , (char*) &psh , sizeof (t_udppsh));
    memcpy(pseudogram + sizeof(t_udppsh) , udph , sizeof(struct udphdr));
    udph->check = csum( (unsigned short*) pseudogram , sizeof(t_udppsh) + sizeof(struct udphdr));
	free(pseudogram);
}