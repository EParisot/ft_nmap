/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_syn.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: maabou-h <maabou-h@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/05 23:09:42 by maabou-h          #+#    #+#             */
/*   Updated: 2020/09/05 23:11:02 by maabou-h         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

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

static void syn_iphdr(t_opt *opt, struct iphdr* iph, char *datagram, char *addr)
{
    iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id = htons(0);
	iph->frag_off = htons(16384);
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(opt->localhost);
	iph->daddr = inet_addr(addr);
    iph->check = csum((unsigned short *) datagram, iph->tot_len >> 1);
}

static void syn_tcphdr(struct tcphdr* tcph)
{
    tcph->source = htons(9999);
	tcph->dest = htons(80);
	tcph->seq = htonl(1105024978);
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
    syn_iphdr(opt, (struct iphdr *)datagram, datagram, addr);
    syn_tcphdr((struct tcphdr *)(datagram + sizeof(struct ip)));
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