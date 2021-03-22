#include "../includes/ft_nmap.h"

static void     my_packet_handler(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet)
{
	t_result *result = (t_result *)(((t_probe_arg*)args)->result);
	const struct ip* iphdr;
	const struct tcphdr* tcphdr;
	const struct icmp* icmp;
	(void)header;

	packet += 14;
	iphdr = (struct ip*)packet;
	packet += 4*iphdr->ip_hl;
	tcphdr = (struct tcphdr*)packet;
	icmp = (struct icmp*)packet;
	pthread_mutex_lock(((t_probe_arg*)args)->lock);
	switch (iphdr->ip_p)
	{
		case IPPROTO_TCP:
			result->states[((t_probe_arg*)args)->scan_idx] = \
				tcphdr->th_flags & TH_URG ? 'U' \
				: tcphdr->th_flags & TH_SYN ? 'a' \
				: tcphdr->th_flags & TH_PUSH ? 'P' \
				: tcphdr->th_flags & TH_RST ? 'R' \
				: tcphdr->th_flags & TH_ACK ? 'S' \
				: tcphdr->th_flags & TH_FIN ? 'F' \
				: '*';
			break;

		case IPPROTO_UDP:
			result->states[((t_probe_arg*)args)->scan_idx] = 'u';
			break;

		case IPPROTO_ICMP:
			result->states[((t_probe_arg*)args)->scan_idx] = (icmp->icmp_type == 3) ? 'e' : 'i';
			break;

		default:
			result->states[((t_probe_arg*)args)->scan_idx] = '*';
			break;
	}
	pthread_mutex_unlock(((t_probe_arg*)args)->lock);
	//printf("%s %d\n", result->ip, result->port);
}

static int	wait_response(t_thread_arg *targs)
{
	const int		str_len = 256;
	char			str_filter[str_len];
	t_probe_arg		*args;
	struct timeval 	start;
	struct timeval 	curr;
	t_result		*result;
	int				ret = 0;

	ft_bzero(str_filter, str_len);
	ft_strcat(str_filter, "tcp or udp and dst ");
	ft_strcat(str_filter, (char*)targs->opt->localhost);
	ft_strcat(str_filter, " and src port ");
	char *str_port = ft_itoa(targs->port);
	ft_strcat(str_filter, str_port);
	free(str_port);
	ft_strcat(str_filter, " and dst port 32323 or icmp and dst ");
	ft_strcat(str_filter, (char*)targs->opt->localhost);

	if (nmap_pcapsetup(targs->opt, targs->sock_id, str_filter) == -1)
		return (-1);
	send_probe(targs->opt, targs->ip, targs->port, targs->scan, targs->opt->sockets[targs->sock_id]->sock_fd);
	if ((args = (t_probe_arg*)malloc(sizeof(t_probe_arg))) == NULL)
	{
		printf("ft_nmap: Error probe failed malloc\n");
		return (1);
	}
	ft_bzero(args, sizeof(t_probe_arg));
	args->lock = targs->opt->lock;
	result = &targs->opt->results[targs->ip_idx][targs->port_idx];
	args->result = result;
	args->scan = targs->scan;
	args->scan_idx = targs->scan_idx;
	pcap_setnonblock(targs->opt->sockets[targs->sock_id]->handle, 1, NULL);
	gettimeofday(&start, NULL);
	while (1)
	{
		ret = pcap_dispatch(targs->opt->sockets[targs->sock_id]->handle, 1, my_packet_handler, (uint8_t *)args);
		if (ret)
			break;
		gettimeofday(&curr, NULL);
		if ((curr.tv_sec - start.tv_sec) > TIMEOUT)
		{
			pcap_breakloop(targs->opt->sockets[targs->sock_id]->handle);
			//printf("TIMEOUT %s %d\n", result->ip, result->port);
			result->states[targs->scan_idx] = 'T';
			break;
		}
	}
	pcap_setnonblock(targs->opt->sockets[targs->sock_id]->handle, 0, NULL);
	free(args);
	return (0);
}

void	*probe(void *vargs)
{
	t_thread_arg *args = (t_thread_arg *)vargs;
	wait_response(args);
	args->opt->sockets[args->sock_id]->available = 1;
	pthread_mutex_lock(args->opt->lock);
	pcap_close(args->opt->sockets[args->sock_id]->handle);
	pcap_freecode(&(args->opt->sockets[args->sock_id]->filter));
	pthread_mutex_unlock(args->opt->lock);
	free(args);
	return (NULL);
}