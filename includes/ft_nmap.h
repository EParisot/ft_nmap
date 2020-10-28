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
# define TIMEOUT 5

# include "../libft/libft.h"
# include <stdlib.h>
# include <stdio.h>
# include <pcap.h> // for PCAP_ERRBUF_SIZE
// also using -D_GNU_SOURCE for all types in pcap.h that were cancelled by the POSIC_C_SOURCE preproc
# include <arpa/inet.h> // for inet_pton()
#include <stdbool.h>
# include <net/ethernet.h> // for ETHERTYPE macros
# include <unistd.h> // for geteuid
# include <sys/types.h> // for geteuid
# include <pthread.h> // for threads
# include <ifaddrs.h> // for getifaddr and ifaddr structcs
# include <netinet/ip.h> // for iphdr struct
# include <netinet/ip_icmp.h> // for iphdr struct
# include <netinet/tcp.h> // for tcphdr struct
#include<netinet/udp.h>
# include <signal.h>
# include<string.h>
# include<sys/socket.h>

bool g_stop;

typedef struct          s_device
{
    char                *device;
    char                errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32         subnet_mask;
    bpf_u_int32         ip;
}                       t_device;

typedef struct			s_socket
{
	int32_t					sock_fd;
	int32_t					available;
	pthread_t			*thread;
	pcap_t      		*handle;
	struct bpf_program  filter;
}						t_socket;

typedef struct  s_opt
{
	uint8_t			*localhost;
    uint8_t     	threads;    /* 250 threads rentrent large dans un uint8_t */
    uint8_t     	scanflag;   /* 8 bits suffisent pour caler tous les flags possibles en binaire */ 
	t_list			*ranges;	/* ranges option */
    t_list      	*ports;     /* liste de ports */
    t_list      	*ips;       /* nombre d'ip variable, une liste c'est bien */
    t_device    	*dev;
	t_socket		**sockets;
	FILE			*logfile;
	pthread_mutex_t	*lock;
}               t_opt;

typedef struct	s_range
{
	int32_t			start;
	int32_t		end;
}				t_range;

typedef struct	s_thread_arg
{
	t_opt				*opt;
	int32_t					sock_id;
	struct sockaddr_in	*ip;
	int32_t					port;
	uint8_t				scan;
	pthread_mutex_t		*lock;
}				t_thread_arg;

typedef struct	s_probe_arg
{
	FILE			*logfile;
	pthread_mutex_t	*lock;
	int32_t			port;
	uint8_t			scan;
}				t_probe_arg;

typedef struct s_psh
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
    struct tcphdr tcp;
}               t_psh;

typedef struct s_udppsh
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
}       t_udppsh;

# define T_FIN 1 << 1
# define T_SYN 1 << 2
# define T_RST 1 << 3
# define T_PUSH 1 << 4
# define T_ACK 1 << 5
# define T_URG 1 << 6

void		geniphdr(struct ip *ip, uint8_t *addr);
void    	gentcphdr(struct tcphdr* tcph, int32_t port, uint8_t flag);
uint16_t    genpshdr(struct tcphdr *tcph, uint32_t s_addr, uint8_t *local);

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
uint8_t            *getlocalhost(t_opt *opt);
unsigned short	csum(unsigned short *ptr, int nbytes);
/****************************/

/*		scan_*.c			*/
int scantcp(t_opt *opt, int32_t sock, uint8_t *addr, int32_t port, uint8_t flag, int z);
int scanudp(t_opt *opt, int sock, char *addr, int port);
/****************************/

#endif
