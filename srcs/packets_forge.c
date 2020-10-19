/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   packets_forge.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eparisot <eparisot@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/24 23:09:42 by eparisot          #+#    #+#             */
/*   Updated: 2020/08/24 23:11:02 by eparisot         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_nmap.h"

/*static int probe_connect(int sock, char *addr, int port)
{
    int ret;
    struct sockaddr_in remote = {0};

    ret = -1;
    remote.sin_addr.s_addr = inet_addr(addr);
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    ret = connect(sock, (struct sockaddr *)&remote, sizeof(struct sockaddr_in));
    return ret;
}*/


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

int		send_probe(t_opt *opt, struct sockaddr_in *addr, int port, uint8_t scan, int sock)
{
	char	str_addr[INET_ADDRSTRLEN];

	ft_bzero(str_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &addr->sin_addr, str_addr, INET_ADDRSTRLEN);
	//printf("socket: %d Sending probe, packet type %d to %s on port %d\n", sock, scan, str_addr, port);
	/*if (probe_connect(sock, str_addr, port) < 0)
    {
        printf("Could not create socket\n");
        return -1;
    }*/
    switch((char)scan)
    {
        case (1 << (1)):
            scan_syn(opt, sock, str_addr, port);
            break ;
        case (1 << (2)):
            scan_null(opt, sock, str_addr, port);
            break ;
        case (1 << (3)):
            scan_ack(opt, sock, str_addr, port);
            break ;
        case (1 << (4)):
            scan_fin(opt, sock, str_addr, port);
            break ;
        case (1 << (5)):
            scan_xmas(opt, sock, str_addr, port);
            break ;
        case (1 << (6)):
            scan_udp(opt, sock, str_addr, port);
            break ;
        default:
            printf("already scannedall\n");
            break ;
    }
    return (0);
}