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

static void     my_packet_handler(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet)
{
	FILE 				*logfile = (FILE *)(((t_probe_arg*)args)->logfile);
	int					port = (int)(((t_probe_arg*)args)->port);
	uint8_t				scan = (uint8_t)(((t_probe_arg*)args)->scan);
	int					str_len = 64;
	char				str[str_len];
	int 				buf_len = 1024;
	char				*buf = (char*)malloc(buf_len);
	ft_bzero(buf, buf_len);	
	ft_strcat(buf, "------------------------\n");

	ft_bzero(str, str_len);
	sprintf(str, "Total packet available: %d bytes\n", header->caplen);
    ft_strcat(buf, str);

	const struct ether_header* ethh;
    const struct ip* iph;
    const struct tcphdr* tcph;
    //const struct udphdr* udph;
	ethh = (struct ether_header*)packet;
    if (ntohs(ethh->ether_type) == ETHERTYPE_IP)
	{
		iph = (struct ip*)(packet + sizeof(struct ether_header));
		if (iph->ip_p == IPPROTO_TCP)
		{
			ft_bzero(str, str_len);
			sprintf(str, "%d TCP packet: %d\n", scan, port);
    		ft_strcat(buf, str);
            tcph = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			if (tcph->th_flags & TH_SYN)
			{
					ft_bzero(str, str_len);
					sprintf(str, "SYN: %d\n", port);
    				ft_strcat(buf, str);
			}
			else if (tcph->th_flags & TH_RST)
			{
					ft_bzero(str, str_len);
					sprintf(str, "RST: %d\n", port);
    				ft_strcat(buf, str);
			}
		}
		else if (iph->ip_p == IPPROTO_UDP)
		{
			ft_bzero(str, str_len);
			sprintf(str, "UDP packet: %d\n", port);
    		ft_strcat(buf, str);
            //udph = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
		}
	}
    ft_strcat(buf, "------------------------\n");
	if (logfile)
		fwrite(buf, ft_strlen(buf), 1, logfile);
	printf("%s", buf);
}

static t_device *init_ndevice()
{
    // on chope l'interface, sur ma vm c'est enp0s3 par exemple
    t_device	        *dev;
	pcap_if_t	        *alldevsp;

	alldevsp = NULL;
    if ((dev = (t_device *)malloc(sizeof(t_device))) == NULL)
		return (NULL);
	ft_bzero(dev, sizeof(dev));
	if (pcap_findalldevs(&alldevsp, dev->errbuf))
		return (NULL);
	dev->device = ft_strdup(alldevsp->name);
	pcap_freealldevs(alldevsp);
    return (dev);
}

static inline int   nmap_pcapsetup(t_opt *opt, int sock_id, char* const filter)
{
    if (pcap_lookupnet(opt->dev->device, &(opt->dev->ip), &(opt->dev->subnet_mask), opt->dev->errbuf) == -1)
    {
        printf("ft_nmap: Could not get information for device: %s\n", opt->dev->device);
        opt->dev->ip = 0;
        opt->dev->subnet_mask = 0;
    }
    opt->sockets[sock_id]->handle = pcap_open_live(opt->dev->device, 1028, 0, 1000, opt->dev->errbuf);
    if (opt->sockets[sock_id]->handle == NULL)
    {
        fprintf(stderr, "ft_nmap: Cannot open interface %s", opt->dev->device);
        return (-1);
    }
	pthread_mutex_lock(opt->lock);
    if (pcap_compile(opt->sockets[sock_id]->handle, &(opt->sockets[sock_id]->filter), filter, 0, opt->dev->ip) == -1)
    {
        printf("ft_nmap: Bad filter - %s\n", pcap_geterr(opt->sockets[sock_id]->handle));
        return (-1);
    }
    if (pcap_setfilter(opt->sockets[sock_id]->handle, &(opt->sockets[sock_id]->filter)) == -1)
    {
        printf("ft_nmap: Error setting filter - %s\n", pcap_geterr(opt->sockets[sock_id]->handle));
        return (-1);
    }
	pthread_mutex_unlock(opt->lock);
    return (1);
}

static int	wait_response(t_opt *opt, int sock_id, struct sockaddr_in *addr, int port, uint8_t scan)
{
	char			str_addr[INET_ADDRSTRLEN];
	char			*str_port;
	char			*str_filter;
	t_probe_arg		*args;
	//struct timeval	start;
	//struct timeval	curr;
	//int				str_len = 64;
	//char			str[str_len];

	ft_bzero(str_addr, INET_ADDRSTRLEN);
	if ((str_filter = (char *)malloc(46 + 2 * INET_ADDRSTRLEN + 6)) == NULL)
		return (-1);
	ft_bzero(str_filter, 46 + 2 * INET_ADDRSTRLEN + 6);

	if (scan == 128)
		ft_strcat(str_filter, "udp and src host ");
	else
		ft_strcat(str_filter, "tcp and src host ");
	inet_ntop(AF_INET, &addr->sin_addr, str_addr, INET_ADDRSTRLEN);
	ft_strcat(str_filter, str_addr);
	
	ft_strcat(str_filter, " and dst host ");
	ft_strcat(str_filter, opt->localhost);
	
	str_port = ft_itoa(port);
	ft_strcat(str_filter, " and src port ");
	ft_strcat(str_filter, str_port);
	
	printf("%d: listening %s\n", scan, str_filter);
	if (nmap_pcapsetup(opt, sock_id, str_filter) == -1)
		return (-1);
	if ((args = (t_probe_arg*)malloc(sizeof(t_probe_arg))) == NULL)
	{
		printf("ft_nmap: Error probe failed malloc\n");
		return (1);
	}
	args->logfile = opt->logfile;
	args->lock = opt->lock;
	args->port = port;
	args->scan = scan;
	//pcap_setnonblock(opt->sockets[sock_id]->handle, 1, NULL);
	pcap_dispatch(opt->sockets[sock_id]->handle, 1, my_packet_handler, (uint8_t *)args);
	/*gettimeofday(&start, NULL);
	while (1)
	{
		gettimeofday(&curr, NULL);
		if ((curr.tv_sec - start.tv_sec) * 1000000 > 1)
		{
			pcap_breakloop(opt->sockets[sock_id]->handle);
			ft_bzero(str, str_len);
			sprintf(str, "Probe Timeout on port %d with %d scan\n", port, scan);
			if (opt->logfile)
				fwrite(str, 1, 1, opt->logfile);
			printf("%s", str);
			break;
		}
	}*/
	free(str_port);
	free(str_filter);
	free(args);
	return (0);
}

void	*probe(void *vargs)
{
	t_thread_arg *args = (t_thread_arg *)vargs;

	send_probe(args->opt, args->ip, args->port, args->scan, args->opt->sockets[args->sock_id]->sock_fd);
	wait_response(args->opt, args->sock_id, args->ip, args->port, args->scan);
	args->opt->sockets[args->sock_id]->available = 1;
	pcap_close(args->opt->sockets[args->sock_id]->handle);
	pcap_freecode(&(args->opt->sockets[args->sock_id]->filter)); // !!!! Unauthorized fct, to re-implement !!!!!!
	free(args);
	return (NULL);
}

void		sig_handler(int num_sig)
{
	if (num_sig == SIGINT)
	{
		printf("SIGINT, waiting for timeouts to finish...\n");
		g_stop = true;
	}
	return ;
}

static int	nmap_sender(t_opt *opt)
{
	t_list	*tmp_ips;
	t_list	*tmp_port;
	int 	sock_id = 0;
	int		proto = IPPROTO_TCP;

	g_stop = false;
	signal(SIGINT, sig_handler);
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
	if ((opt->sockets = (t_socket **)malloc(opt->threads * sizeof(t_socket*))) == NULL)
		return (-1);

	// nmap loop
	for (int scan = (1 << 1); scan <= 0xFF && g_stop == false; scan = scan << 1)
	{
		tmp_ips = opt->ips;
		tmp_port = opt->ports;
		if (scan & opt->scanflag)
		{
			// open sockets and create threads
			if (scan == 128)
				proto = IPPROTO_UDP;
			for (int i = 0; i < opt->threads && g_stop == false; i++)
			{
				if ((opt->sockets[i] = (t_socket *)malloc(sizeof(t_socket))) == NULL)
					return (-1);
				if ((opt->sockets[i]->sock_fd = socket(AF_INET, SOCK_RAW, proto)) < 0)
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
				while (tmp_port && g_stop == false)
				{
					while (g_stop == false)
					{//printf("try %d\n", *(int *)(tmp_port->content));
						if (opt->sockets[sock_id]->available == 1)
						{//printf("sending to %d\n", *(int *)(tmp_port->content));
							t_thread_arg *args;

							if ((args = (t_thread_arg *)malloc(sizeof(t_thread_arg))) == NULL)
								return (-1);
							args->opt = opt;
							args->sock_id = sock_id;
							args->ip = (struct sockaddr_in *)(tmp_ips->content);
							args->port = *(int *)(tmp_port->content);
							args->scan = scan & opt->scanflag;
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
				}
				tmp_port = opt->ports;
				tmp_ips = tmp_ips->next;
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
	}
	pthread_mutex_destroy(opt->lock);
	free(opt->lock);
	free(opt->sockets);
	return (0);
}

int		nmap_wrapper(t_opt *opt)
{	
	if ((opt->dev = init_ndevice()) == NULL)
		return (-1);
	if (getuid() == 0)
	{
		opt->localhost = getlocalhost(opt);
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