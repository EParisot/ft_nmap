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
	if (opt->ports)
		ft_lstdel(&opt->ports, del);
	if (opt->ips)
		ft_lstdel(&opt->ips, del);
	free(opt);
}

int		main(int ac, char **av)
{
	t_opt	*opt;
	int 	ret = 0;

	if ((opt = (t_opt *)malloc(sizeof(t_opt))) == NULL)
		return (-1);
	ft_bzero(opt, sizeof(opt));
	opt->ports = NULL;
	opt->ips = NULL;
	if (ac <= 1)
	{
		bad_usage(NULL, 0);
		ret = (-1);
	}
	if (ret == 0)
		ret = nmap_optloop(opt, ac, av);
	clean_env(opt);
	return (ret);
}
