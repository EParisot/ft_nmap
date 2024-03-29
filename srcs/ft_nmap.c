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

void print_results(t_opt *opt, int ip_count, struct timeval start, struct timeval end)
{
	struct servent *service;
	const int str_len = 256;
	char str[str_len];
	char str2[str_len];
	bool to_print = false;
	bool printed = false;
	int closed = 0;

	ft_bzero(str, str_len);
	sprintf(str, "%u ip(s) and %u port(s)\n", (unsigned int)ft_lstcount(opt->ips), (unsigned int)ft_lstcount(opt->ports));
	write(1, str, ft_strlen(str));
	if (opt->logfile)
		fwrite(str, ft_strlen(str), 1, opt->logfile);
	for (size_t i = 0; i < ft_lstcount(opt->ips); i++)
	{
		closed = 0;
		ft_bzero(str, str_len);
		sprintf(str, "\nip: %s\nPORT\tSERVICE NAME\tRESULT\n------------------------------------------------------------------\n", opt->results[i][0].ip);
		write(1, str, ft_strlen(str));
		if (opt->logfile)
			fwrite(str, ft_strlen(str), 1, opt->logfile);
		for (size_t p = 0; p < ft_lstcount(opt->ports); p++)
		{
			service = getservbyport(htons(opt->results[i][p].port), NULL);
			ft_bzero(str2, str_len);
			if (service)
				sprintf(str2, "%5d\t%-16s\t", opt->results[i][p].port, service->s_name);
			else
				sprintf(str2, "%5d\t%-16s\t", opt->results[i][p].port, "(null)");
			printed = false;
			for (size_t s = 0; s < 6; s++)
			{
				if (opt->scanflag & (1 << (s+1)))
				{
					to_print = false;
					ft_bzero(str, str_len);
					if (s == 0)
					{
						sprintf(str, "SYN(%s) ", opt->results[i][p].states[s] == 'a' ? "open" : opt->results[i][p].states[s] == 'T' ? "filtered" : "closed");
						if (opt->results[i][p].states[s] == 'a')
							to_print = true;
					}
					else if (s == 1 || s == 3 || s == 4)
					{
						sprintf(str, "%s(%s) ", s == 1 ? "NULL" : s == 3 ? "FIN" : "XMAS",\
						opt->results[i][p].states[s] == 'R' ? "closed" : opt->results[i][p].states[s] == 'e' ? "filtered" : "open|filtered");
						if (opt->results[i][p].states[s] != 'R')
							to_print = true;
					}
					else if (s == 2)
					{
						sprintf(str, "ACK(%s) ", opt->results[i][p].states[s] == 'R' ? "unfiltered" : "filtered");
						if (opt->results[i][p].states[s] == 'R')
							to_print = true;
					}
					else
					{
						sprintf(str, "UDP(%s)", opt->results[i][p].states[s] == 'i' ? "filtered" : opt->results[i][p].states[s] == 'u' ? "open" : "closed");
						if (opt->results[i][p].states[s] == 'u' || opt->results[i][p].states[s] == 'i')
							to_print = true;
					}
					if (to_print)
					{
						if (!printed)
						{
							write(1, str2, ft_strlen(str2));
							if (opt->logfile)
								fwrite(str2, ft_strlen(str2), 1, opt->logfile);
							printed = true;
						}
						write(1, str, ft_strlen(str));
						if (opt->logfile)
							fwrite(str, ft_strlen(str), 1, opt->logfile);
					}
					to_print = false;
				}
			}
			if (printed)
			{
				ft_bzero(str, str_len);
				sprintf(str, "\n");
				write(1, str, ft_strlen(str));
				if (opt->logfile)
					fwrite(str, ft_strlen(str), 1, opt->logfile);
			} else {
				closed++;
			}
		}
		ft_bzero(str, str_len);
		sprintf(str, "\n%u port(s) closed\n", closed);
		write(1, str, ft_strlen(str));
		if (opt->logfile)
			fwrite(str, ft_strlen(str), 1, opt->logfile);
	}
	ft_bzero(str, str_len);
	sprintf(str, "\n# ft_nmap done -- %ld IP address (%d host(s) up) scanned in %.2f seconds\n", ft_lstcount(opt->ips), ip_count,
		   (float)((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)) / 1000000);
	write(1, str, ft_strlen(str));
	if (opt->logfile)
		fwrite(str, ft_strlen(str), 1, opt->logfile);
}

static int nmap_sender(t_opt *opt)
{
	t_list *tmp_ips;
	t_list *tmp_port;
	int sock_id = 0;
	int proto = IPPROTO_TCP;
	struct timeval start;
	struct timeval end;
	size_t ip_idx = 0;
	size_t port_idx = 0;
	size_t scan_idx = 0;
	int ip_count = 0;
	g_stop = false;
	
	//signal(SIGINT, sig_handler);
	struct sigaction new_action, old_action;
	new_action.sa_handler = sig_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction(SIGINT, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
    	sigaction(SIGINT, &new_action, NULL);

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
			ip_count = 0;
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
				ft_bzero(opt->sockets[i]->thread, sizeof(pthread_t));
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
								// clear the thread before it starts, no matter if started before
								pthread_join(*(opt->sockets[sock_id]->thread), NULL);
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
			// clean threads and sockets
			for (int i = 0; i < opt->threads; i++)
			{
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
	print_results(opt, ip_count, start, end);
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