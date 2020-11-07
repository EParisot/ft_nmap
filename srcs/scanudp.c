#include "../includes/ft_nmap.h"

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