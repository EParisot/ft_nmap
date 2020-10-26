#include "../includes/ft_nmap.h"

typedef struct __attribute__((packed)) s_udppsh
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
}	t_udppsh;


unsigned short chksum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

static struct sockaddr_in probe_filludppacket(char **pkt, char *addr, int port)
{
	char *datagram = *pkt;
	char *pseudogram;
	struct sockaddr_in  sin;
    t_udppsh   psh;


    ft_memset(datagram, 0, 4096);
    struct iphdr *iph = (struct iphdr *) datagram;
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
     
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(addr);
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr);
    iph->id = htonl(9999); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr(addr);    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;
    //Ip checksum
    iph->check = csum((unsigned short *) datagram, iph->tot_len);
    //UDP header
    udph->source = htons(9001);
    udph->dest = htons(port);
    udph->len = htons(8); //tcp header size
    udph->check = 0; //leave checksum 0 now, filled later by pseudo header
     
    //Now the UDP checksum using the pseudo header
    psh.source_address = inet_addr(addr);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr));
     
    int psize = sizeof(t_psh) + sizeof(struct udphdr);
    pseudogram = malloc(psize);
     
    memcpy(pseudogram , (char*) &psh , sizeof (t_udppsh));
    memcpy(pseudogram + sizeof(t_udppsh) , udph , sizeof(struct udphdr));
     
    udph->check = chksum( (unsigned short*) pseudogram , psize);
     
    return (sin);
}

int scanudp(t_opt *opt, int32_t sock, uint8_t *addr, int32_t port)
{
    struct timeval tv;
    char    pkt[4096];
    char *tmp = pkt;
    struct sockaddr_in dest;
    (void)opt;

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv)) < 0)
    {
        printf("ft_nmap: timeout sending probe\n");
        return -1;
    }
    dest = probe_filludppacket(&tmp, (char*)addr, port);
    printf("sending packet\n");
    if (sendto(sock, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
	{
		printf ("Error sending udp packet.\n");
		return -1;
	}
    return 0;
}