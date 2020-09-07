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
	if (opt->dev)
	{
		if (opt->dev->device)
			free(opt->dev->device);	
		free(opt->dev);
	}
	free(opt);
}

int		main(int ac, char **av)
{
	t_opt	*opt;
	int 	ret = 0;

	if ((opt = (t_opt *)malloc(sizeof(t_opt))) == NULL)
		return (-1);
	ft_bzero(opt, sizeof(opt));
	opt->ranges = NULL;
	opt->ports = NULL;
	opt->ips = NULL;
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
	    	ret = ft_nmap(opt);
			printf("Device: %s\n", opt->dev->device);
		}
	}
	clean_env(opt);
	return (ret);
}