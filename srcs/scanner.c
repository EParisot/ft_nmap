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
	uint8_t	str_addr[INET_ADDRSTRLEN];

	ft_bzero(str_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &addr->sin_addr, (char*)str_addr, INET_ADDRSTRLEN);
    // si on a un scan tcp fin/null/xmas il faut envoyer ca au prealable
    if (scan != (1 << 1))
    {
        scantcp(opt, sock, str_addr, port, T_SYN, 1);
        scantcp(opt, sock, str_addr, port, T_ACK, 1);
    }
    // on envoie 3 probes a chaque fois maintenant
    switch((char)scan)
    {
        case (1 << (1)):
            scantcp(opt, sock, str_addr, port, T_SYN, 3);
            break ;
        case (1 << (2)):
            scantcp(opt, sock, str_addr, port, 0, 3);
            break ;
        case (1 << (3)):
            scantcp(opt, sock, str_addr, port, T_ACK, 1);
            break ;
        case (1 << (4)):
            scantcp(opt, sock, str_addr, port, T_FIN, 3);
            break ;
        case (1 << (5)):
            scantcp(opt, sock, str_addr, port, T_FIN | T_PUSH | T_URG, 3);
            break ;
        case (1 << (6)):
            scanudp(opt, sock, (char*)str_addr, port);
            break ;
        default:
            printf("already scannedall\n");
            break ;
    }
    return (0);
}