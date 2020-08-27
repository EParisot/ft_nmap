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

typedef struct s_env
{
	char		*ip_str;
	char		*file_name;
	int			speedup;
	int			scan_type;
	t_list		*ports;

}				t_env;

typedef struct  s_opt
{
    uint8_t     threads;    /* 250 threads rentrent large dans un uint8_t */
    uint8_t     scanflag;   /* 8 bits suffisent pour caler tous les flags possibles en binaire */ 
    t_lst       *ports;     /* liste de ports */
    t_lst       *ips;       /* nombre d'ip variable, une liste c'est bien */
}               t_opt;

#endif
