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
            scantcp(opt, sock, str_addr, port, T_SYN);
            break ;
        case (1 << (2)):
            scantcp(opt, sock, str_addr, port, 0);
            break ;
        case (1 << (3)):
            scantcp(opt, sock, str_addr, port, T_ACK);
            break ;
        case (1 << (4)):
            scantcp(opt, sock, str_addr, port, T_FIN);
            break ;
        case (1 << (5)):
            scantcp(opt, sock, str_addr, port, T_FIN | T_PUSH | T_URG);
            break ;
        case (1 << (6)):
            scanudp(opt, sock, str_addr, port);
            break ;
        default:
            printf("already scannedall\n");
            break ;
    }
    return (0);
}