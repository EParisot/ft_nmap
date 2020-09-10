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
    if ((dev->handle = (pcap_t *)malloc(sizeof(dev->handle))) == NULL)
		return (NULL);
	ft_bzero(dev->handle, sizeof(dev->handle));
    return (dev);
}

int		        ft_nmap(t_opt *opt)
{
	int snapshot_len = 1028;
	int promiscuous = 0;
	int timeout = 1000;

	if ((opt->dev = init_ndevice()) == NULL)
		return (-1);
	if (getuid() == 0)
	{
		if (pcap_lookupnet(opt->dev->device, &(opt->dev->ip), &(opt->dev->subnet_mask), opt->dev->errbuf) == -1)
        {
            printf("ft_nmap: Could not get information for device: %s\n", opt->dev->device);
            opt->dev->ip = 0;
            opt->dev->subnet_mask = 0;
        }
        opt->dev->handle = pcap_open_live(opt->dev->device, snapshot_len, promiscuous, timeout, opt->dev->errbuf);
        if (opt->dev->handle == NULL)
        {
            fprintf(stderr, "ft_nmap: Cannot open interface %s", opt->dev->device);
            return (-1);
        }
        if (pcap_compile(opt->dev->handle, &(opt->dev->filter), "host 45.33.32.156", 0, opt->dev->ip) == -1)
        {
            printf("ft_nmap: Bad filter - %s\n", pcap_geterr(opt->dev->handle));
            return -1;
        }
        if (pcap_setfilter(opt->dev->handle, &(opt->dev->filter)) == -1)
        {
            printf("ft_nmap: Error setting filter - %s\n", pcap_geterr(opt->dev->handle));
            return -1;
        }
        printf("ft_nmap: entering pcap_loop\n");
        for (int i = 0; i < 10; i++)
        { pcap_dispatch(opt->dev->handle, 1, my_packet_handler, NULL);}
        //pcap_loop(opt->dev->handle, 10, my_packet_handler, NULL);
        printf("ft_nmap: exiting pcap_loop\n");
        pcap_close(opt->dev->handle);
	}
	else
	{
		bad_usage(NULL, -1);
		return (-1);
	}
    return 0;
}