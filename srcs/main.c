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

static void	del(void *addr, size_t size)
{
	(void)size;
	free(addr);
}

static void	clean_env(t_env *env)
{
	ft_lstdel(&env->ports, del);
	free(env);
}

static int	parse_ports(int ac, char **av, t_env *env)
{
	(void)ac;
	(void)av;
	(void)env;
	// TODO parse ports opt here
	return (0);
}

static int	parse_opt(int ac, char **av, t_env *env)
{
	// TODO parse options here
	parse_ports(ac, av, env);
	return (0);
}

int			main(int ac, char **av)
{
	t_env	*env;

	if ((env = (t_env *)malloc(sizeof(t_env))) == NULL)
		return (-1);
	if (parse_opt(ac, av, env))
		return (-1);
	clean_env(env);
	return (0);
}
