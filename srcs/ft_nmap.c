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
}

static t_device *init_ndevice()
{
    // on chope l'interface, sur ma vm c'est enp0s3 par exemple
    t_device	*dev;
	pcap_if_t	*alldevsp;

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

int		        ft_nmap(t_opt *opt)
{
	// je teste le loop pcap ici, pour l'instant avec NPACKETS
	// comme limite de paquets a ecouter
	int snapshot_len = 1028;
	int promiscuous = 0;
	int timeout = 1000;

	if ((opt->dev = init_ndevice()) == NULL)
		return (-1);
	if (getuid() == 0)
	{
		if ((opt->dev->handle = pcap_open_live(opt->dev->device, snapshot_len, promiscuous, timeout, opt->dev->errbuf)) == NULL)
			return (-1);
	}
	else
	{
		bad_usage(NULL, -1);
		return (-1);
	}
	pcap_dispatch(opt->dev->handle, NPACKETS, my_packet_handler, NULL);
	pcap_close(opt->dev->handle);
	return (0);
}