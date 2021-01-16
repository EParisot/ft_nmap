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

int send_probe(t_opt *opt, struct sockaddr_in *addr, int port, uint8_t scan, int sock)
{
	uint8_t str_addr[INET_ADDRSTRLEN];

	ft_bzero(str_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &addr->sin_addr, (char *)str_addr, INET_ADDRSTRLEN);
	scantcp(opt, sock, str_addr, port, T_SYN, 55443);
	scantcp(opt, sock, str_addr, port, T_ACK, 55445);
	switch ((char)scan)
	{
	case (1 << (1)):
		scantcp(opt, sock, str_addr, port, T_SYN, 55444);
		scantcp(opt, sock, str_addr, port, T_SYN, 32323);
		break;
	case (1 << (2)):
		scantcp(opt, sock, str_addr, port, 0, 55444);
		scantcp(opt, sock, str_addr, port, 0, 32323);
		break;
	case (1 << (3)):
		scantcp(opt, sock, str_addr, port, T_ACK, 55444);
		scantcp(opt, sock, str_addr, port, T_ACK, 32323);
		break;
	case (1 << (4)):
		scantcp(opt, sock, str_addr, port, T_FIN, 55444);
		scantcp(opt, sock, str_addr, port, T_FIN, 32323);
		break;
	case (1 << (5)):
		scantcp(opt, sock, str_addr, port, T_FIN | T_PUSH | T_URG, 55444);
		scantcp(opt, sock, str_addr, port, T_FIN | T_PUSH | T_URG, 32323);
		break;
	case (1 << (6)):
		scanudp(opt, sock, (char *)str_addr, port, 55444);
		scanudp(opt, sock, (char *)str_addr, port, 32323);
		break;
	default:
		printf("already scannedall\n");
		break;
	}
	return (0);
}