/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: maabou-h <maabou-h@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/05 23:09:42 by maabou-h          #+#    #+#             */
/*   Updated: 2020/09/05 23:11:02 by maabou-h         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_nmap.h"

void	del(void *addr, size_t size)
{
	(void)size;
	free(addr);
}

void	clean_env(t_opt *opt)
{
	if (opt->ranges)
		ft_lstdel(&opt->ranges, del);
	if (opt->ports)
		ft_lstdel(&opt->ports, del);
	if (opt->ips)
		ft_lstdel(&opt->ips, del);
	if (opt->localhost)
		free(opt->localhost);
	if (opt->dev)
	{
		if (opt->dev->device)
			free(opt->dev->device);
		free(opt->dev);
	}
	free(opt);
}

int	    	bad_usage(const char *arg, int context)
{
    const char *usage = "ft_nmap by eparisot and maabou-h @42 Paris\n\
                        Usage: ft_nmap [--help] [--ports [NUMBER/RANGE]] --ip IPADDRESS [--speedup [NUMBER]] [--scan [TYPE]]\n\
                        \t\tft_nmap [--help] [--ports [NUMBER/RANGE]] --file FILENAME [--speedup [NUMBER]] [--scan [TYPE]]\n\
                        \t--help\tPrint this help screen\n\
                        \t--ports\tports to scan (eg: 1-10 or 1,2,3 or 1,5-15) (1-65535 max)\n\
                        \t--ip\t\tip addresses to scan in dot format\n\
                        \t--file\t\tFile name containing IP addresses to scan,\n\
                        \t--speedup\t[250 max] number of parallel threads to use\n\
                        \t--scan\t\tSYN/NULL/FIN/XMAS/ACK/UDP";

    if (context)
	{
		if (context > 0)
			fprintf(stderr, "argument error: %s, context %d\n", arg, context);
		else if (context == -1)
			fprintf(stderr, "permission error\n");
	}
	else
		printf("%s\n", usage);	
	return (-1);
}