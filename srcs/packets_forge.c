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

int		send_probe(struct sockaddr_in *addr, int port, uint8_t scan)
{
	char	str_addr[INET_ADDRSTRLEN];

	ft_bzero(str_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &addr->sin_addr, str_addr, INET_ADDRSTRLEN);
	printf("Sending packet type %d to %s on port %d\n", scan, str_addr, port);
	return (0);
}