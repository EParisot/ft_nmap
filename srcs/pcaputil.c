#include "../includes/ft_nmap.h"

t_device *init_ndevice()
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

int   nmap_pcapsetup(t_opt *opt, int sock_id, char* filter)
{
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
    return (1);
}