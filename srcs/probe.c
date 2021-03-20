#include "../includes/ft_nmap.h"

static void     my_packet_handler(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet)
{
	t_result			*result = (t_result *)(((t_probe_arg*)args)->result);

	//result->states = ;

	const struct ip* iphdr;
	const struct tcphdr* tcphdr;
	//char iphi[256], srcip[256], dstip[256];
	(void)header;

	packet += 14;
	iphdr = (struct ip*)packet;
	//ft_strcpy(srcip, inet_ntoa(iphdr->ip_src));
	//ft_strcpy(dstip, inet_ntoa(iphdr->ip_dst));

	packet += 4*iphdr->ip_hl;
	tcphdr = (struct tcphdr*)packet;
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
			result->states[((t_probe_arg*)args)->scan_idx] = 'i';
			break;

		default:
			result->states[((t_probe_arg*)args)->scan_idx] = '*';
			break;
	}
	pthread_mutex_unlock(((t_probe_arg*)args)->lock);
	printf("%s %d\n", result->ip, result->port);

	// OLD VERSION
	
	/*FILE 				*logfile = (FILE *)(((t_probe_arg*)args)->logfile);
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
	free(buf);*/
}

static int	wait_response(t_thread_arg *targs)
{
	char			str_filter[64];
	t_probe_arg		*args;
	//int				str_len = 64;
	//char			str[str_len];
	struct timeval 	start;
	struct timeval 	curr;
	t_result		*result;
	int				ret = 0;

	ft_bzero(str_filter, 64);
	ft_strcat(str_filter, "tcp or udp and dst ");
	ft_strcat(str_filter, (char*)targs->opt->localhost);
	ft_strcat(str_filter, " and src port ");
	char *str_port = ft_itoa(targs->port);
	ft_strcat(str_filter, str_port);
	free(str_port);
	ft_strcat(str_filter, " and dst port 32323 or icmp and dst ");
	ft_strcat(str_filter, (char*)targs->opt->localhost);
	printf("%s\n", str_filter);

	if (nmap_pcapsetup(targs->opt, targs->sock_id, str_filter) == -1)
	{ printf("error\n");
		return (-1);}
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
	pcap_freecode(&(args->opt->sockets[args->sock_id]->filter)); // !!!! Unauthorized fct, to re-implement !!!!!!
	pthread_mutex_unlock(args->opt->lock);
	free(args);
	return (NULL);
}