/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: maabou-h <maabou-h@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/05 23:09:42 by maabou-h          #+#    #+#             */
/*   Updated: 2020/09/05 23:11:02 by maabou-h         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_nmap.h"

static int retmsg(const char *str, const char *arg, int ret)
{
	fprintf(stderr, str, arg);
	return (ret);
}

static void remove_doublons(t_list *ports)
{
	t_list *tmp_lst = ports;
	t_list *last_port = NULL;
	int last_val = 0;

	while (tmp_lst)
	{
		if (*(int *)(tmp_lst->content) > last_val)
		{
			last_val = *(int *)tmp_lst->content;
			last_port = tmp_lst;
			tmp_lst = tmp_lst->next;
		}
		else
		{
			last_port->next = tmp_lst->next;
			ft_lstdelone(&tmp_lst, del);
			tmp_lst = last_port->next;
		}
	}
}

static int append_range(t_opt *options, char **dash_tab)
{
	t_list *new_ranges_lst;
	t_list *new_ports_lst;
	t_range range;

	range.start = ft_atoi(dash_tab[0]);
	if (ft_tablen(dash_tab) > 1)
		range.end = ft_atoi(dash_tab[1]);
	else
		range.end = range.start;
	if (range.end < range.start)
	{
		int tmp = range.start;
		range.start = range.end;
		range.end = tmp;
	}
	if (range.start > 0 && range.start <= 65535 &&
		range.end > 0 && range.end <= 65535)
	{
		for (int i = range.start; i <= range.end; i++)
		{
			if ((new_ports_lst = ft_lstnew(&i, sizeof(int))) == NULL)
				return (-1);
			if (options->ports)
				ft_lstaddend(&options->ports, new_ports_lst);
			else
				options->ports = new_ports_lst;
		}
		if ((new_ranges_lst = ft_lstnew(&range, sizeof(range))) == NULL)
			return (-1);
		if (options->ranges)
			ft_lstaddend(&options->ranges, new_ranges_lst);
		else
			options->ranges = new_ranges_lst;
	}
	return (0);
}

static int read_ports(t_opt *options, char *const args[], int *optind)
{
	char **comas_tab;
	char **dash_tab;
	int ret = 0;

	if (args[*optind + 1] == NULL)
		return (retmsg("ft_nmap: error: missing argument near %s\n", "--port", -1));
	if ((comas_tab = ft_strsplit(args[*optind + 1], ',')) == NULL)
		return (retmsg("ft_nmap: error parsing port argument: %s\n", args[*optind + 1], -1));
	for (size_t i = 0; i < ft_tablen(comas_tab); i++)
	{
		if ((dash_tab = ft_strsplit(comas_tab[i], '-')) == NULL)
			return (retmsg("ft_nmap: error parsing port argument: %s\n", args[*optind + 1], -1));
		ret = append_range(options, dash_tab);
		for (size_t j = 0; dash_tab[j]; j++)
			free(dash_tab[j]);
		free(dash_tab);
		if (ret)
		{
			retmsg("ft_nmap: error parsing port argument: %s\n", args[*optind + 1], -1);
			break;
		}
	}
	(*optind)++;
	for (size_t i = 0; comas_tab[i]; i++)
		free(comas_tab[i]);
	free(comas_tab);
	return (ret);
}

static int append_ip(t_opt *options, char *const ip)
{
	char *resolved_ip;
	t_list *new_lst;
	struct sockaddr_in sa;

	if ((resolved_ip = malloc(INET_ADDRSTRLEN)) == NULL)
		return (-1);
	bzero(resolved_ip, INET_ADDRSTRLEN);
	if (dns_lookup(ip, resolved_ip)) 
	{
		free(resolved_ip);
		return (-1);
	}
	ft_strcpy(ip, resolved_ip);
	free(resolved_ip);
	if (inet_addr(ip) == INADDR_NONE)
		return (-1);
	inet_pton(AF_INET, ip, &sa.sin_addr);
	if ((new_lst = ft_lstnew(&sa, sizeof(sa))) == NULL) 
		return (-1);
	if (options->ips)
		ft_lstaddend(&options->ips, new_lst);
	else
		options->ips = new_lst;
	return (0);
}

static int fread_ipaddr(t_opt *options, char *const args[], int *optind)
{
	FILE *fp;
	char *ipbuf;
	int fd;
	int ret;

	ret = 0;
	if (args[*optind + 1] == NULL || ((fp = fopen(args[*optind + 1], "r")) == NULL))
		return (args[*optind + 1] == NULL ? retmsg("ft_nmap: error: missing argument near %s\n", "--file", -1)
										  : retmsg("ft_nmap: error: bad argument for --file option %s\n", args[*optind + 1], -1));
	fd = fileno(fp);
	while (get_next_line(fd, &ipbuf) > 0)
	{
		if (!ipbuf || !ipbuf[0])
			break;
		if (append_ip(options, ipbuf) == -1)
			ret = retmsg("ft_nmap: error with ip in file: %s\n", ipbuf ? ipbuf : NULL, -1);
		free(ipbuf);
		if (ret)
		{
			fclose(fp);
			return (ret);
		}
	}
	free(ipbuf);
	fclose(fp);
	(*optind)++;
	return (0);
}

static int read_ipaddr(t_opt *options, char *const args[], int *optind)
{
	if (args[*optind + 1] == NULL)
		return (retmsg("ft_nmap: error: missing argument near %s\n", "--ip", -1));
	if (append_ip(options, args[*optind + 1]) == -1)
		return (retmsg("ft_nmap: error with ip: %s\n", args[*optind + 1], -1));
	(*optind)++;
	return (0);
}

static int read_speedup(t_opt *options, char *const args[], int *optind)
{
	int threads_nb = 0;

	if (args[*optind + 1] == NULL)
		return (retmsg("ft_nmap: error: missing argument near %s\n", "--speedup", -1));
	threads_nb = ft_atoi(args[*optind + 1]);
	if (threads_nb <= 250)
		options->threads = threads_nb;
	else
		options->threads = 250;
	(*optind)++;
	return (0);
}

static int append_scantype(t_opt *options, char *type)
{
	const char *typelist[7] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP", 0};

	if (!type || type[0] == '\0')
		return (1);
	for (size_t i = 0; i < 6; i++)
	{
		if (!ft_strcmp(typelist[i], type))
		{
			options->scanflag += (1 << (i + 1));
			return (0);
		}
	}
	return (-1);
}

static int read_scantypes(t_opt *options, char *const args[], int *optind)
{
	char **flags;
	int ret = 0;

	if (args[*optind + 1] == NULL)
		return (retmsg("ft_nmap: error: missing argument near %s\n", "--scan", -1));
	if ((flags = ft_strsplit(args[*optind + 1], '/')) == NULL)
		return (retmsg("ft_nmap: error with scantype: %s\n", args[*optind + 1], -1));
	for (size_t i = 0; i < ft_tablen(flags); i++)
	{
		ret = append_scantype(options, flags[i]);
		if (ret || ret == -1)
		{
			if (ret == -1)
				return (retmsg("ft_nmap: error with scantype: %s\n", flags[i], -1));
			break;
		}
	}
	for (size_t i = 0; flags[i]; i++)
		free(flags[i]);
	free(flags);
	(*optind)++;
	return (0);
}

static int fread_logfile(t_opt *options, int nargs, char *const args[], int *optind)
{
	FILE *fp;
	int ret;

	ret = 0;
	if (args[*optind + 1] == NULL)
		return (retmsg("ft_nmap: error: missing argument near %s\n", "--log", -1));
	if ((fp = fopen(args[*optind + 1], "w")) == NULL)
		return (retmsg("ft_nmap: error: cannot create %s file\n", "--log", -1));
	options->logfile = fp;
	fwrite("# ft_nmap scan initiated as: ", 29, 1, options->logfile);
	for (int i = 0; i < nargs; i++)
	{
		fwrite(args[i], ft_strlen(args[i]), 1, options->logfile);
		fwrite(" ", 1, 1, options->logfile);
	}
	fwrite("\n\n", 2, 1, options->logfile);

	(*optind)++;
	return (ret);
}

static char nmap_getopt(int nargs, char *const args[], int *optind)
{
	if (*optind == nargs || !ft_strcmp("--help", args[*optind]))
	{
		return 'h';
	}
	else if (!ft_strcmp("--ports", args[*optind]) && *optind + 1 < nargs)
	{
		return 'p';
	}
	else if (!ft_strcmp("--ip", args[*optind]) && *optind + 1 < nargs)
	{
		return 'i';
	}
	else if (!ft_strcmp("--file", args[*optind]) && *optind + 1 < nargs)
	{
		return 'f';
	}
	else if (!ft_strcmp("--speedup", args[*optind]) && *optind + 1 < nargs)
	{
		return 'v';
	}
	else if (!ft_strcmp("--scan", args[*optind]) && *optind + 1 < nargs)
	{
		return 's';
	}
	else if (!ft_strcmp("--log", args[*optind]) && *optind + 1 < nargs)
	{
		return 'l';
	}
	return 'h';
}

int ft_cmp(void *a, void *b)
{
	return (*(int *)b - *(int *)a);
}

static int set_defaults(t_opt *options)
{
	char *dft_ports[3];
	int nb_to_scan = options->threads;

	dft_ports[0] = "1\0";
	dft_ports[1] = "1024\0";
	dft_ports[2] = NULL;
	if (options->ips == NULL)
	{
		bad_usage("--ip", 0);
		return (-1);
	}
	if (options->ports == NULL)
		if (append_range(options, dft_ports))
			return (-1);
	ft_lstsort(options->ports, ft_cmp);
	remove_doublons(options->ports);
	nb_to_scan = ft_lstcount(options->ips) * ft_lstcount(options->ports);
	if (options->threads == 0)
		options->threads = 1;
	else if (nb_to_scan < options->threads)
		options->threads = nb_to_scan;
	if (options->scanflag == 0)
		options->scanflag = 0x7f; // 0xff when all flags active
	return (0);
}

static void print_summary(t_opt *options)
{
	t_list *tmp_ranges = options->ranges;
	t_list *tmp_ips = options->ips;
	char *flagstr[7] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP", 0};

	printf("IP(s) :");
	if (options->logfile)
		fwrite("IP(s) :", 7, 1, options->logfile);
	while (tmp_ips)
	{
		printf(" %s", inet_ntoa(((struct sockaddr_in *)tmp_ips->content)->sin_addr));
		if (options->logfile)
		{
			char str[16];
			sprintf(str, " %s", inet_ntoa(((struct sockaddr_in *)tmp_ips->content)->sin_addr));
			fwrite(str, ft_strlen(str), 1, options->logfile);
		}
		tmp_ips = tmp_ips->next;
		(tmp_ips) ? printf(",") : printf("\n");
		if (options->logfile)
			(tmp_ips) ? fwrite(",", 1, 1, options->logfile) : fwrite("\n", 1, 1, options->logfile);
	}
	printf("Ports : ");
	if (options->logfile)
		fwrite("Ports : ", 8, 1, options->logfile);
	while (tmp_ranges)
	{
		if (((t_range *)(tmp_ranges->content))->end > ((t_range *)(tmp_ranges->content))->start)
		{
			printf("%d-%d", ((t_range *)(tmp_ranges->content))->start, ((t_range *)(tmp_ranges->content))->end);
			if (options->logfile)
			{
				char str[11];
				sprintf(str, "%d-%d", ((t_range *)(tmp_ranges->content))->start, ((t_range *)(tmp_ranges->content))->end);
				fwrite(str, ft_strlen(str), 1, options->logfile);
			}
		}
		else
		{
			printf("%d", ((t_range *)(tmp_ranges->content))->start);
			if (options->logfile)
			{
				char str[11];
				sprintf(str, "%d", ((t_range *)(tmp_ranges->content))->start);
				fwrite(str, ft_strlen(str), 1, options->logfile);
			}
		}
		tmp_ranges = tmp_ranges->next;
		(tmp_ranges) ? printf(",") : printf("\n");
		if (options->logfile)
		{
			(tmp_ranges) ? fwrite(",", 1, 1, options->logfile) : fwrite("\n", 1, 1, options->logfile);
		}
	}
	printf("Threads : %d\n", options->threads);
	printf("Packets types :");
	if (options->logfile)
	{
		char str[15];
		sprintf(str, "Threads : %d\n", options->threads);
		fwrite(str, ft_strlen(str), 1, options->logfile);
		fwrite("Packets types :", 15, 1, options->logfile);
	}
	for (int i = 0; i < 6; i++)
	{
		((options->scanflag >> (i + 1)) & 1) ? printf(" %s", flagstr[i]) : 0;
		(i < 5) ? printf(",") : printf("\n\n");
		if (options->logfile)
		{
			if ((options->scanflag >> (i + 1)) & 1)
			{
				char str[2];
				sprintf(str, " %s", flagstr[i]);
				fwrite(str, ft_strlen(str), 1, options->logfile);
				(i < 5) ? fwrite(",", 1, 1, options->logfile) : fwrite("\n\n", 2, 1, options->logfile);
			}
		}
	}
}

int nmap_optloop(t_opt *options, int nargs, char *const args[])
{
	char opt = 0;
	int optind = 1;
	int ret = 0;

	while (ret == 0 && optind < nargs && (opt = nmap_getopt(nargs, args, &optind)))
	{
		switch (opt)
		{
		case 'h':
			ret = bad_usage(NULL, 0);
			break;
		case 'p':
			ret = read_ports(options, args, &optind);
			break;
		case 'i':
			ret = read_ipaddr(options, args, &optind);
			break;
		case 'f':
			ret = fread_ipaddr(options, args, &optind);
			break;
		case 'v':
			ret = read_speedup(options, args, &optind);
			break;
		case 's':
			ret = read_scantypes(options, args, &optind);
			break;
		case 'l':
			ret = fread_logfile(options, nargs, args, &optind);
			break;
			if (ret)
				return (-1);
		}
		optind++;
	}
	if (set_defaults(options))
		return (-1);
	if (ret != -1)
	{
		printf("# ft_nmap scan initiated as: ");
		for (int i = 0; i < nargs; ++i)
			printf("%s ", args[i]);
		printf("\n\n");
		print_summary(options);
	}
	return (ret);
}