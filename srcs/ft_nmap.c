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

void sig_handler(int num_sig)
{
	if (num_sig == SIGINT)
	{
		printf("SIGINT, waiting for timeouts to finish...\n");
		g_stop = true;
	}
	return;
}

int is_open(char *states)
{
	for (int i = 0; i < 7; ++i)
	{
		if (states[i])
		{
			if ((i == 2 && states[i] != 'T') || (i != 2 && states[i] != 'R' && states[i] != 'T'))
			{
				return (1);
			}
		}
	}
	return (0);
}

void print_results(t_opt *opt)
{
	int closed = 0;
	printf("%u ip(s) and %u port(s)\n", (unsigned int)ft_lstcount(opt->ips), (unsigned int)ft_lstcount(opt->ports));
	if (opt->logfile)
	{
		char str[30];
		sprintf(str, "%u ip(s) and %u port(s)\n", (unsigned int)ft_lstcount(opt->ips), (unsigned int)ft_lstcount(opt->ports));
		fwrite(str, ft_strlen(str), 1, opt->logfile);
	}
	for (size_t i = 0; i < ft_lstcount(opt->ips); i++)
	{
		closed = 0;
		printf("ip: %s\n", opt->results[i][0].ip);
		if (opt->logfile)
		{
			char str[21];
			sprintf(str, "ip: %s\n", opt->results[i][0].ip);
			fwrite(str, ft_strlen(str), 1, opt->logfile);
		}
		for (size_t p = 0; p < ft_lstcount(opt->ports); p++)
		{
			if (is_open(opt->results[i][p].states)) 
			{
				printf("port : %d -> ", opt->results[i][p].port);
				if (opt->logfile)
				{
					char str[15];
					sprintf(str, "port : %d -> ", opt->results[i][p].port);
					fwrite(str, ft_strlen(str), 1, opt->logfile);
				}
				for (size_t s = 0; s < 6; ++s)
				{
					if (s)
					{
						printf(",");
						if (opt->logfile)
							fwrite(",", 1, 1, opt->logfile);
					}
					printf(" %c", opt->results[i][p].states[s]);
					if (opt->logfile)
					{
						char str[3];
						sprintf(str, " %c", opt->results[i][p].states[s]);
						fwrite(str, 1, ft_strlen(str), opt->logfile);
					}
				}
				printf("\n");
				if (opt->logfile)
					fwrite("\n", 1, 1, opt->logfile);
			}
			else
			{
				++closed;
			}
		}
		if (closed)
		{
			printf("Not shown: %d closed ports\n", closed);
			if (opt->logfile)
			{
				char str[32];
				sprintf(str, "Not shown: %d closed ports\n", closed);
				fwrite(str, 1, ft_strlen(str), opt->logfile);
			}
		}
	}
}

static int nmap_sender(t_opt *opt)
{
	t_list *tmp_ips;
	t_list *tmp_port;
	int sock_id = 0;
	int proto = IPPROTO_TCP;
	struct timeval start;
	struct timeval end;
	int ip_count = 0;
	size_t ip_idx = 0;
	size_t port_idx = 0;
	size_t scan_idx = 0;

	g_stop = false;
	signal(SIGINT, sig_handler);
	gettimeofday(&start, NULL);
	if ((opt->lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t))) == NULL)
	{
		printf("ft_nmap: Error mutex malloc failed\n");
		return (1);
	}
	if (pthread_mutex_init(opt->lock, NULL) != 0)
	{
		printf("ft_nmap: Error mutex init failed\n");
		return (1);
	}
	// creates sockets
	if ((opt->sockets = (t_socket **)malloc(opt->threads * sizeof(t_socket *))) == NULL)
		return (-1);

	// creates results
	if ((opt->results = (t_result **)malloc(ft_lstcount(opt->ips) * sizeof(t_result *))) == NULL)
		return (-1);
	tmp_ips = opt->ips;
	tmp_port = opt->ports;
	for (size_t i = 0; i < ft_lstcount(opt->ips); i++)
	{
		if ((opt->results[i] = (t_result *)malloc(ft_lstcount(opt->ports) * sizeof(t_result))) == NULL)
			return (-1);
		for (size_t p = 0; p < ft_lstcount(opt->ports); p++)
		{
			opt->results[i][p].port = *(int *)tmp_port->content;
			ft_strcpy(opt->results[i][p].ip, inet_ntoa(((struct sockaddr_in *)tmp_ips->content)->sin_addr));
			ft_bzero(opt->results[i][p].states, 7);
			tmp_port = tmp_port->next;
		}
		tmp_ips = tmp_ips->next;
		tmp_port = opt->ports;
	}

	// nmap loop
	for (int scan = (1 << 1); scan < 0xFF && g_stop == false; scan = scan << 1)
	{
		ip_idx = 0;
		port_idx = 0;
		tmp_ips = opt->ips;
		tmp_port = opt->ports;
		if (scan & opt->scanflag)
		{
			// open sockets and create threads
			if (scan == 64)
				proto = IPPROTO_RAW;
			for (int i = 0; i < opt->threads && g_stop == false; i++)
			{
				if ((opt->sockets[i] = (t_socket *)malloc(sizeof(t_socket))) == NULL)
					return (-1);
				if ((opt->sockets[i]->sock_fd = socket(PF_INET, SOCK_RAW, proto)) < 0)
				{
					fprintf(stderr, "Error: Socket file descriptor not received\n");
					return (-1);
				}
				opt->sockets[i]->available = 1;
				if ((opt->sockets[i]->thread = (pthread_t *)malloc(sizeof(pthread_t))) == NULL)
					return (-1);
			}
			// loop over ip / ports
			while (tmp_ips && g_stop == false)
			{
				if (ping_ip((struct sockaddr_in *)(tmp_ips->content)) == 0)
				{
					++ip_count;
					port_idx = 0;
					while (tmp_port && g_stop == false)
					{
						while (g_stop == false)
						{
							if (opt->sockets[sock_id]->available == 1)
							{
								t_thread_arg *args;

								if ((args = (t_thread_arg *)malloc(sizeof(t_thread_arg))) == NULL)
									return (-1);
								args->opt = opt;
								args->sock_id = sock_id;
								args->ip = (struct sockaddr_in *)(tmp_ips->content);
								args->port = *(int *)(tmp_port->content);
								args->scan = scan & opt->scanflag;
								args->ip_idx = ip_idx;
								args->port_idx = port_idx;
								args->scan_idx = scan_idx;
								opt->sockets[sock_id]->available = 0;
								if (pthread_create(opt->sockets[sock_id]->thread, NULL, probe, (void *)args))
								{
									fprintf(stderr, "Error: Thread not created\n");
									return (-1);
								}
								break;
							}
							if (sock_id == opt->threads - 1)
								sock_id = 0;
							else
								sock_id++;
						}
						tmp_port = tmp_port->next;
						port_idx++;
					}
				}
				tmp_port = opt->ports;
				tmp_ips = tmp_ips->next;
				ip_idx++;
			}
			// clean sockets
			for (int i = 0; i < opt->threads; i++)
			{
				//printf("Wait threads end\n");
				pthread_join(*(opt->sockets[i]->thread), NULL);
				free(opt->sockets[i]->thread);
				close(opt->sockets[i]->sock_fd);
				free(opt->sockets[i]);
			}
		}
		scan_idx++;
	}
	gettimeofday(&end, NULL);
	pthread_mutex_destroy(opt->lock);
	free(opt->lock);
	free(opt->sockets);
	print_results(opt);
	printf("\n# ft_nmap done -- %ld IP address (%d host(s) up) scanned in %.2f seconds\n", ft_lstcount(opt->ips), ip_count,
		   (float)((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)) / 1000000);
	return (0);
}

int nmap_wrapper(t_opt *opt)
{
	if ((opt->dev = init_ndevice()) == NULL)
		return (-1);
	if (getuid() == 0)
	{
		if ((opt->localhost = getlocalhost(opt)) == NULL)
		{
			printf("ft_nmap error: Please check your network connection !\n");
			return (-1);
		}
		// send probes
		if (nmap_sender(opt))
			return (-1);
	}
	else
	{
		bad_usage(NULL, -1);
		return (-1);
	}
	return 0;
}