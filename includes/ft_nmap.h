/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eparisot <eparisot@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/24 23:09:42 by eparisot          #+#    #+#             */
/*   Updated: 2020/08/24 23:11:02 by eparisot         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H

# define FT_NMAP_H

# include "../libft/libft.h"
# include <stdlib.h>
# include <stdio.h>

typedef struct  s_opt
{
    uint8_t     threads;    /* 250 threads rentrent large dans un uint8_t */
    uint8_t     scanflag;   /* 8 bits suffisent pour caler tous les flags possibles en binaire */ 
    t_list      *ports;     /* liste de ports */
    t_list      *ips;       /* nombre d'ip variable, une liste c'est bien */
}               t_opt;

void	clean_env(t_opt *opt);
void	del(void *addr, size_t size);

int    	bad_usage(const char *arg, int context);						/* Handle error on parsing argument and quit gracefully */

char    nmap_getopt(int nargs, char *const args[], int *optind);		/* Detect option to be treated and how to parse next argument */
int     nmap_optloop(t_opt *options, int nargs, char *const args[]);	/* Iterate through argv to parse arguments from command line */

#endif
