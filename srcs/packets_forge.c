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

int		send_probe(t_opt *opt, struct sockaddr_in *addr, int port, uint8_t scan, int sock)
{
	char	str_addr[INET_ADDRSTRLEN];

	ft_bzero(str_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &addr->sin_addr, str_addr, INET_ADDRSTRLEN);
    switch((char)scan)
    {
        case (1 << (1)):
            scan_syn(opt, sock, str_addr, port);
            break ;
        case (1 << 2):
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