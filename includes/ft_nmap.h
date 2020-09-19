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

# define _POSIX_C_SOURCE 1 // for fileno()
# define NPACKETS 1 // for pcap_loop()

# include "../libft/libft.h"
# include <stdlib.h>
# include <stdio.h>
# include <pcap.h> // for PCAP_ERRBUF_SIZE
// also using -D_GNU_SOURCE for all types in pcap.h that were cancelled by the POSIC_C_SOURCE preproc
# include <arpa/inet.h> // for inet_pton()
# include <net/ethernet.h> // for ETHERTYPE macros
# include <unistd.h> // for geteuid
# include <sys/types.h> // for geteuid
# include <pthread.h> // for threads
# include <ifaddrs.h> // for getifaddr and ifaddr structcs
# include <netinet/ip.h> // for iphdr struct
# include <netinet/tcp.h> // for tcphdr struct
# include<string.h>
# include<sys/socket.h>

typedef struct          s_device
{
    char                *device;
    char                errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32         subnet_mask;
    bpf_u_int32         ip;
}                       t_device;

typedef struct			s_socket
{
	int					sock_fd;
	int					available;
	pthread_t			*thread;
	pcap_t      		*handle;
	struct bpf_program  filter;
}						t_socket;

typedef struct  s_opt
{
	char		*localhost;
    uint8_t     threads;    /* 250 threads rentrent large dans un uint8_t */
    uint8_t     scanflag;   /* 8 bits suffisent pour caler tous les flags possibles en binaire */ 
	t_list		*ranges;	/* ranges option */
    t_list      *ports;     /* liste de ports */
    t_list      *ips;       /* nombre d'ip variable, une liste c'est bien */
    t_device    *dev;
	t_socket	**sockets;
}               t_opt;

typedef struct	s_range
{
	int			start;
	int			end;
}				t_range;

typedef struct	s_thread_arg
{
	t_opt				*opt;
	int					sock_id;
	struct sockaddr_in	*ip;
	int					port;
	uint8_t				scan;
}				t_thread_arg;

/*		errors.c			*/
void	clean_env(t_opt *opt);
void	del(void *addr, size_t size);
int    	bad_usage(const char *arg, int context);						/* Handle error on parsing argument and quit gracefully */
/****************************/

/*		options.c			*/
int             nmap_optloop(t_opt *options, int nargs, char *const args[]);
/****************************/

/*		ft_nmap.c			*/
int		nmap_wrapper(t_opt *opt);
/****************************/

/*		packets_forge.c		*/
int		send_probe(t_opt *opt, struct sockaddr_in *addr, int port, uint8_t scan, int sock);
/****************************/

/*		netutils.c			*/
char            *getlocalhost(t_opt *opt);
unsigned short	csum(unsigned short *ptr, int nbytes);
/****************************/

/*		scan_*.c			*/
int             scan_syn(t_opt *opt, int sock, char *addr, int port);
int             scan_null(t_opt *opt, int sock, char *addr, int port);
int             scan_xmas(t_opt *opt, int sock, char *addr, int port);
/****************************/

#endif
