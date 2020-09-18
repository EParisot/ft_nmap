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
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    printf("------------------------\n");
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);

    /* Print payload in ASCII */
     
    if (payload_length > 0) {
        const unsigned char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
        printf("------------------------\n");
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
	send_probe(args->opt, args->ip, args->port, args->scan, args->opt->sockets[args->sock_id]->sock_fd);
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
	for (int scan = 1; scan <= 0xFF; scan = scan << 1)
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
							args->scan = scan & opt->scanflag;
							//if (pthread_create(opt->sockets[sock_id]->thread, NULL, probe, (void *)args))
							//	return (-1);
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
				while (!opt->sockets[i]->available)
					;
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