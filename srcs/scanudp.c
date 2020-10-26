#include "../includes/ft_nmap.h"

typedef struct __attribute__((packed)) s_udppsh
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
}       t_udppsh;

int scanudp(t_opt *opt, int32_t sock, uint8_t *addr, int32_t port, uint8_t flag, int z) // a restructurer pour avoir 4 args only
{
    struct timeval      tv;
    char                pkt[4096];
    struct sockaddr_in  dest;
    char                *datagram = pkt;
    uint8_t *pseudogram;
    t_udppsh   psh;
	
    int32_t             one = 1;
	const int32_t       *val = &one;
    struct udphdr *udp = (struct udphdr *) (datagram + sizeof(struct iphdr));
    struct iphdr *iph = (struct iphdr*)datagram;

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
    dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = inet_addr((char*)addr);
	iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr);
    iph->id = htonl(9999); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr((char *)addr);    //Spoof the source ip address
    iph->daddr = inet_addr((char*)addr);
    iph->check = csum((unsigned short *) datagram, iph->tot_len);
    udp->source = htons(9001);
    udp->dest = htons(port);
    udp->len = htons(sizeof(struct udphdr));
    udp->check = 0;
	(void)flag;
    (void)opt;

    psh.source_address = inet_addr((char *)addr);
    psh.dest_address = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr));
     
    int psize = sizeof(t_psh) + sizeof(struct udphdr);
    pseudogram = malloc(psize);
     
    memcpy(pseudogram , (char*)&psh , sizeof (t_udppsh));
    memcpy(pseudogram + sizeof(t_udppsh) , udp , sizeof(struct udphdr));
     
    udp->check = csum((unsigned short*) pseudogram , psize);

    while (z--)
    {
        if (sendto(sock, pkt, sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0)
    	{
	    	printf ("Error sending syn packet.\n");
	    	return -1;
	    }
    }
	return (0);
}