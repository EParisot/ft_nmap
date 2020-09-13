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
    // traitement des paquets, pour l'instant je test
    // en affichant juste le type de paquet
	(void)args;
    (void)header;
    struct ether_header *eth_header;
    printf("ft_nmap: entering callback fct\n");
    eth_header = (struct ether_header*)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
        printf("IP\n");
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
        printf("ARP\n");
	else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP)
        printf("Reverse ARP\n");
    else
        printf("Other type man!\n");
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

static inline int   nmap_pcapsetup(t_opt *opt, char* const filter)
{
    if (pcap_lookupnet(opt->dev->device, &(opt->dev->ip), &(opt->dev->subnet_mask), opt->dev->errbuf) == -1)
    {
        printf("ft_nmap: Could not get information for device: %s\n", opt->dev->device);
        opt->dev->ip = 0;
        opt->dev->subnet_mask = 0;
    }
    opt->dev->handle = pcap_open_live(opt->dev->device, 1028, 0, 1000, opt->dev->errbuf);
    if (opt->dev->handle == NULL)
    {
        fprintf(stderr, "ft_nmap: Cannot open interface %s", opt->dev->device);
        return (-1);
    }
    if (pcap_compile(opt->dev->handle, &(opt->dev->filter), filter, 0, opt->dev->ip) == -1)
    {
        printf("ft_nmap: Bad filter - %s\n", pcap_geterr(opt->dev->handle));
        return (-1);
    }
    if (pcap_setfilter(opt->dev->handle, &(opt->dev->filter)) == -1)
    {
        printf("ft_nmap: Error setting filter - %s\n", pcap_geterr(opt->dev->handle));
        return (-1);
    }
    return (1);
}

static int	wait_response(t_opt *opt, struct sockaddr_in *addr, int port)
{
	char	str_addr[INET_ADDRSTRLEN];
	char	*str_port;
	char	*str_filter;

	ft_bzero(str_addr, INET_ADDRSTRLEN);
	if ((str_filter = (char *)malloc(20 + INET_ADDRSTRLEN + 6)) == NULL)
		return (-1);
	ft_bzero(str_filter, 20 + INET_ADDRSTRLEN + 6);
	ft_strcat(str_filter, "src host ");
	inet_ntop(AF_INET, &addr->sin_addr, str_addr, INET_ADDRSTRLEN);
	ft_strcat(str_filter, str_addr);
	str_port = ft_itoa(port);
	ft_strcat(str_filter, " and port ");
	ft_strcat(str_filter, str_port);
	printf("listening %s\n", str_filter);
	if (nmap_pcapsetup(opt, str_filter) == -1)
		return (-1);
	pcap_dispatch(opt->dev->handle, 1, my_packet_handler, NULL);
	free(str_port);
	free(str_filter);
	return (0);
}

void	*probe(void *vargs)
{
	t_thread_arg *args = (t_thread_arg *)vargs;
	*args->opt->sockets[args->sock_id]->available = 0;
	send_probe(args->ip, args->port, args->scan);
	if (wait_response(args->opt, args->ip, args->port))
		return (NULL);
	*args->opt->sockets[args->sock_id]->available = 1;
	pcap_close(args->opt->dev->handle);
	pcap_freecode(&(args->opt->dev->filter)); // !!!! Unauthorized fct, to re-implement !!!!!!
	free(args);
	return (NULL);
}

static int	nmap_sender(t_opt *opt)
{
	t_list	*tmp_ips = opt->ips;
	t_list	*tmp_port = opt->ports;
	int 	sock_id = 0;

	// creates sockets
	if ((opt->sockets = (t_socket **)malloc(opt->threads * sizeof(t_socket*))) == NULL)
		return (-1);

	// nmap loop
	for (int scan = 1; scan <= 32; scan *= 2)
	{
		if (scan & opt->scanflag)
		{
			// open sockets
			for (int i = 0; i < opt->threads; i++)
			{
				if ((opt->sockets[i] = (t_socket *)malloc(sizeof(t_socket))) == NULL)
					return (-1);
				if ((opt->sockets[i]->sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
				{
					fprintf(stderr, "Error: Socket file descriptor not received\n");
					return (-1);
				}
				if ((opt->sockets[i]->available = (int *)malloc(sizeof(int))) == NULL)
					return (-1);
				*opt->sockets[i]->available = 1;
				if ((opt->sockets[i]->thread = (pthread_t *)malloc(sizeof(pthread_t))) == NULL)
					return (-1);
			}
			// loop over ip / ports
			while (tmp_ips)
			{
				while (tmp_port)
				{
					while (1)
					{
						if (*opt->sockets[sock_id]->available == 1)
						{
							/*printf("start_thread\n");*/
							t_thread_arg *args;

							if ((args = (t_thread_arg *)malloc(sizeof(t_thread_arg))) == NULL)
								return (-1);
							args->opt = opt;
							args->sock_id = sock_id;
							args->ip = (struct sockaddr_in *)(tmp_ips->content);
							args->port = *(int *)(tmp_port->content);
							args->scan = scan;
							/*if (pthread_create(opt->sockets[sock_id]->thread, NULL, probe, (void *)args))
								return (-1);*/
							probe(args);
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
				//pthread_join(*opt->sockets[i]->thread, NULL);
				free(opt->sockets[i]->thread);
				free(opt->sockets[i]->available);
				close(opt->sockets[i]->sock_fd);
				free(opt->sockets[i]);
			}
		}
	}
	free(opt->sockets);
	return (0);
}

int		nmap_wrapper(t_opt *opt)
{	
	if ((opt->dev = init_ndevice()) == NULL)
		return (-1);
	if (getuid() == 0)
	{
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