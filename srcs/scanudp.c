#include "../includes/ft_nmap.h"

static struct sockaddr_in genudppkt(char **pkt, char *addr, int port, char *host)
{
    char *datagram = *pkt;
    char *pseudogram;
    struct sockaddr_in  sin;
    struct iphdr *iph;
    struct udphdr *udph;
    t_udppsh   psh;


    ft_memset(datagram, 0, 4096);
    iph = (struct iphdr *) datagram;
    udph = (struct udphdr *) (datagram + sizeof (struct ip));
     
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(addr);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr);
    iph->id = htonl(9999);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(addr);
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum((unsigned short *) datagram, iph->tot_len);

    udph->source = htons(9001);
    udph->dest = htons(port);
    udph->len = htons(8);
    udph->check = 0;

    psh.source_address = inet_addr(host);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr));
    
    pseudogram = malloc(sizeof(t_udppsh) + sizeof(struct udphdr));
    memcpy(pseudogram , (char*) &psh , sizeof (t_udppsh));
    memcpy(pseudogram + sizeof(t_udppsh) , udph , sizeof(struct udphdr));
    udph->check = csum( (unsigned short*) pseudogram , sizeof(t_udppsh) + sizeof(struct udphdr));
    return (sin);
}

int scanudp(t_opt *opt, int sock, char *addr, int port)
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
    dest = genudppkt(&tmp, addr, port, (char*)opt->localhost);
    if (sendto(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        printf ("Error sending udp packet.\n");
        return -1;
    }
    return 1;
}