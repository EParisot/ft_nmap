/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eparisot <eparisot@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/24 23:09:42 by eparisot          #+#    #+#             */
/*   Updated: 2020/08/24 23:11:02 by eparisot         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_nmap.h"

int		main(int ac, char **av)
{
	t_opt	*opt;
	int 	ret = 0;

	if ((opt = (t_opt *)malloc(sizeof(t_opt))) == NULL)
		return (-1);
	ft_bzero(opt, sizeof(opt));
	opt->localhost = NULL;
	opt->ranges = NULL;
	opt->ports = NULL;
	opt->ips = NULL;
	opt->sockets = NULL;
	opt->dev = NULL;
	opt->threads = 0;
	opt->scanflag = 0;
	opt->logfile = 0;
	if (ac <= 1)
	{
		bad_usage(NULL, 0);
		ret = (-1);
	}
	if (ret == 0)
	{
		ret = nmap_optloop(opt, ac, av); // will return -1 if bad argument for option
		if (ret == 0)
		{
	    	ret = nmap_wrapper(opt);
			//printf("Device: %s\n", opt->dev->device);
		}
	}
	clean_env(opt);
	return (ret);
}