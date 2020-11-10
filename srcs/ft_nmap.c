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
	//int					port = (int)(((t_probe_arg*)args)->port);
	//uint8_t				scan = (uint8_t)(((t_probe_arg*)args)->scan);
	//t_result			**results = (t_result **)(((t_probe_arg*)args)->results);
	int					str_len = 256;
	char				str[str_len];
	int 				buf_len = 1024;
	char				*buf = (char*)malloc(buf_len);

	const struct ip* iphdr;
	const struct tcphdr* tcphdr;
	const struct icmp* icmphdr;
	const struct udphdr* udphdr;
	char iphi[256], srcip[256], dstip[256];
	(void)header;

	ft_bzero(buf, buf_len);
	packet += 14;
	iphdr = (struct ip*)packet;
	ft_strcpy(srcip, inet_ntoa(iphdr->ip_src));
	ft_strcpy(dstip, inet_ntoa(iphdr->ip_dst));
	sprintf(iphi, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
			ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
			4*iphdr->ip_hl, ntohs(iphdr->ip_len));
	packet += 4*iphdr->ip_hl;
	switch (iphdr->ip_p)
	{
		case IPPROTO_TCP:
			tcphdr = (struct tcphdr*)packet;
			ft_bzero(str, str_len);
			sprintf(str, "TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->th_sport),
					dstip, ntohs(tcphdr->th_dport));
			ft_strcat(buf, str);
			ft_bzero(str, str_len);
			sprintf(str, "%s\n", iphi);
			ft_strcat(buf, str);
			ft_bzero(str, str_len);
			sprintf(str, "%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
					(tcphdr->th_flags & TH_URG ? 'U' : '*'),
					(tcphdr->th_flags & TH_ACK ? 'A' : '*'),
					(tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
					(tcphdr->th_flags & TH_RST ? 'R' : '*'),
					(tcphdr->th_flags & TH_SYN ? 'S' : '*'),
					(tcphdr->th_flags & TH_FIN ? 'F' : '*'),
					ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack),
					ntohs(tcphdr->th_win), 4*tcphdr->th_off);
			ft_strcat(buf, str);
			break;

		case IPPROTO_UDP:
			udphdr = (struct udphdr*)packet;
			ft_bzero(str, str_len);
			sprintf(str, "UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->uh_sport),
					dstip, ntohs(udphdr->uh_dport));
				ft_strcat(buf, str);
			ft_bzero(str, str_len);
			sprintf(str, "%s\n", iphi);
			ft_strcat(buf, str);
			break;

		case IPPROTO_ICMP:
			icmphdr = (struct icmp*)packet;
			ft_bzero(str, str_len);
			sprintf(str, "ICMP %s -> %s\n", srcip, dstip);
			ft_strcat(buf, str);
			ft_bzero(str, str_len);
			sprintf(str, "%s\n", iphi);
			ft_strcat(buf, str);
			ft_bzero(str, str_len);
			sprintf(str, "Type:%d Code:%d ID:%d Seq:%d\n", (int)(icmphdr->icmp_type), (int)(icmphdr->icmp_code),
					(int)ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), (int)ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
			ft_strcat(buf, str);
			break;
	}
	ft_strcat(buf, "------------------------\n");
	pthread_mutex_lock(((t_probe_arg*)args)->lock);
	if (logfile)
		fwrite(buf, ft_strlen(buf), 1, logfile);
	printf("%s", buf);
	pthread_mutex_unlock(((t_probe_arg*)args)->lock);
	free(buf);
}

static t_device *init_ndevice()
{
    // on chope l'interface, sur ma vm c'est enp0s3 par exemple
    t_device	        *dev;
	pcap_if_t	        *alldevsp = NULL;

    if ((dev = (t_device *)malloc(sizeof(t_device))) == NULL)
		return (NULL);
	ft_bzero(dev, sizeof(t_device));
	if (pcap_findalldevs(&alldevsp, dev->errbuf))
		return (NULL);
	dev->device = ft_strdup((alldevsp)->name);
	pcap_freealldevs(alldevsp);
    return (dev);
}

static inline int   nmap_pcapsetup(t_opt *opt, int sock_id, char* filter)
{
	//pthread_mutex_lock(opt->lock);
    if (pcap_lookupnet(opt->dev->device, &(opt->dev->ip), &(opt->dev->subnet_mask), opt->dev->errbuf) == -1)
    {
        printf("ft_nmap: Could not get information for device: %s\n", opt->dev->device);
        opt->dev->ip = 0;
        opt->dev->subnet_mask = 0;
    }
    opt->sockets[sock_id]->handle = pcap_open_live(opt->dev->device, 1024, 1, 1000, opt->dev->errbuf);
    if (opt->sockets[sock_id]->handle == NULL)
    {
        fprintf(stderr, "ft_nmap: Cannot open interface %s", opt->dev->device);
        return (-1);
    }
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
	//pthread_mutex_unlock(opt->lock);
    return (1);
}

static int	wait_response(t_opt *opt, int sock_id, struct sockaddr_in *addr, int port, uint8_t scan)
{
	char			str_addr[INET_ADDRSTRLEN];
	char			str_filter[64];
	t_probe_arg		*args;
	//int			str_len = 64;
	//char			str[str_len];
	struct timeval 	start;
	struct timeval 	curr;
	int				ret = 0;

	ft_bzero(str_filter, 64);
	ft_strcat(str_filter, "dst host ");
	ft_strcat(str_filter, (char*)opt->localhost);
	ft_strcat(str_filter, " and src port ");
	char *str_port = ft_itoa(port);
	ft_strcat(str_filter, str_port);
	free(str_port);

	//printf("%s\n", str_filter);

	if (nmap_pcapsetup(opt, sock_id, str_filter) == -1)
		return (-1);
	if ((args = (t_probe_arg*)malloc(sizeof(t_probe_arg))) == NULL)
	{
		printf("ft_nmap: Error probe failed malloc\n");
		return (1);
	}
	ft_strcpy(inet_ntoa(addr->sin_addr), str_addr);
	args->lock = opt->lock;
	args->addr = str_addr;
	args->port = port;
	args->scan = scan;
	args->results = opt->results;
	pcap_setnonblock(opt->sockets[sock_id]->handle, 1, NULL);
	gettimeofday(&start, NULL);
	while (1)
	{
		ret = pcap_dispatch(opt->sockets[sock_id]->handle, 1, my_packet_handler, (uint8_t *)args);
		if (ret)
			break;
		gettimeofday(&curr, NULL);
		if ((curr.tv_sec - start.tv_sec) > TIMEOUT)
		{
			pcap_breakloop(opt->sockets[sock_id]->handle);
			/*ft_bzero(str, str_len);
			sprintf(str, "Probe Timeout on port %d with %d scan, %d\n", port, scan, ret);
			ft_strcat(str, "------------------------\n");
			pthread_mutex_lock(opt->lock);
			if (opt->logfile)
				fwrite(str, 1, 1, opt->logfile);
			printf("%s", str);
			pthread_mutex_unlock(opt->lock);*/
			break;
		}
	}
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
	struct timeval 	start;
	struct timeval 	end;

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
	if ((opt->sockets = (t_socket **)malloc(opt->threads * sizeof(t_socket*))) == NULL)
		return (-1);

	// creates results
	if ((opt->results = (t_result **)malloc(ft_lstcount(opt->ips) * sizeof(t_result *))) == NULL)
		return (-1);
	for (size_t i = 0; i < ft_lstcount(opt->ips); i++)
		if ((opt->results[i] = (t_result *)malloc(ft_lstcount(opt->ports) * sizeof(t_result))) == NULL)
			return (-1);

	// nmap loop
	for (int scan = (1 << 1); scan < 0xFF && g_stop == false; scan = scan << 1)
	{
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
	gettimeofday(&end, NULL);
	pthread_mutex_destroy(opt->lock);
	free(opt->lock);
	free(opt->sockets);
	printf("\n# ft_nmap done -- %ld IP address ( host up) scanned in %.2f seconds\n", ft_lstcount(opt->ips) , \
		(float)((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)) / 1000000);
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