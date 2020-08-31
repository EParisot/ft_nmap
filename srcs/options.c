#include "../includes/ft_nmap.h"

int	    	bad_usage(const char *arg, int context)
{
    const char *usage = "ft_nmap by eparisot and maabou-h @42 Paris\n\
                        Usage: ft_nmap [--help] [--ports [NUMBER/RANGE]] --ip IPADDRESS [--speedup [NUMBER]] [--scan [TYPE]]\n\
                        \t\tft_nmap [--help] [--ports [NUMBER/RANGE]] --file FILENAME [--speedup [NUMBER]] [--scan [TYPE]]\n\
                        \t--help\tPrint this help screen\n\
                        \t--ports\tports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n\
                        \t--ip\t\tip addresses to scan in dot format\n\
                        \t--file\t\tFile name containing IP addresses to scan,\n\
                        \t--speedup\t[250 max] number of parallel threads to use\n\
                        \t--scan\t\tSYN/NULL/FIN/XMAS/ACK/UDP";

    if (context)
		fprintf(stderr, "argument error: %s, context %d\n", arg, context);
	else
		printf("%s\n", usage);	
	return (-1);
}

static int	append_range(t_opt *options, char **dash_tab)
{
	t_list	*new_lst;
	t_range	range;


	range.start = ft_atoi(dash_tab[0]);
	if (ft_tablen(dash_tab) > 1)
		range.end = ft_atoi(dash_tab[1]);
	else
		range.end = range.start;
	if ((new_lst = ft_lstnew(&range, sizeof(range))) == NULL)
		return (-1);
	if (options->ports)
		ft_lstaddend(&options->ports, new_lst);
	else
		options->ports = new_lst;
	return (0);
}

static int	read_ports(t_opt *options, char *const args[], int *optind)
{
	char	**comas_tab;
	char	**dash_tab;
	int		ret;

	ret = 0;
	if ((comas_tab = ft_strsplit(args[*optind + 1], ',')) == NULL)
		return (-1);
	for (size_t i = 0; i < ft_tablen(comas_tab); i++)
	{
		if ((dash_tab = ft_strsplit(comas_tab[i], '-')) == NULL)
			return (-1);
		ret = append_range(options, dash_tab);
		for (size_t j = 0; dash_tab[j]; j++)
			free(dash_tab[j]);
		free(dash_tab);
		if (ret)
			break;
	}
	(*optind)++;
	for (size_t i = 0; comas_tab[i]; i++)
		free(comas_tab[i]);
	free(comas_tab);
	return (ret);
}

static inline int	append_ip(t_opt *options, char *const ip)
{
	t_list				*new_lst;
	struct sockaddr_in	sa;
	
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

int		fread_ipaddr(t_opt *options, char *const args[], int *optind)	//TODO
{
	FILE				*fp;
	char				*ipbuf;
	int					fd;

	if ((fp = fopen(args[*optind + 1], "r")) == NULL)
		return (-1);
	fd = fileno(fp);
	while (get_next_line(fd, &ipbuf) > 0)
	{
		if (!ipbuf || !ipbuf[0])
			break ;
		if (append_ip(options, ipbuf) == -1)
			return (-1);
		free(ipbuf);
	}
	fclose(fp);
	(*optind)++;
	return (0);
}

int		read_ipaddr(t_opt *options, char *const args[], int *optind)	//TODO
{
	if (args[*optind + 1] == NULL)
		return (-1);
	if (append_ip(options, args[*optind + 1]) == -1)
		return (-1);
	(*optind)++;
	return (0);
}

int		read_speedup(t_opt *options, char *const args[], int *optind)
{
	options->threads = ft_atoi(args[*optind + 1]);
	(*optind)++;
	return (0);
}

static inline int	append_scantype(t_opt *options, char *type)
{
	const char	*typelist[7] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP", 0};

	if (!type || type[0] == '\0')
		return (1);
	for (size_t i = 0; i < 6; i++)
	{
		if (!ft_strcmp(typelist[i], type))
			options->scanflag += (1 << (i + 1));
	}
	return (0);
}

int		read_scantypes(t_opt *options, char *const args[], int *optind)
{
	char	**flags;
	int		ret = 0;

	if ((flags = ft_strsplit(args[*optind + 1], '/')) == NULL)
		return (-1);
	for (size_t i = 0; i < ft_tablen(flags); i++)
	{
		ret = append_scantype(options, flags[i]);
		if (ret)
			break;
	}
	for (size_t i = 0; flags[i]; i++)
		free(flags[i]);
	free(flags);
	(*optind)++;
	return (0);
}

char    nmap_getopt(int nargs, char *const args[], int *optind)	//TODO
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
	return 'h';
}

static int		set_defaults(t_opt *options)
{
	char	*dft_ports[2];

	dft_ports[0] = "0\0";
	dft_ports[1] = "1024\0";
	/*if (options->ips == NULL)
	{
		bad_usage("--ip", 0);
		return (-1);
	}*/
	if (options->ports == NULL)
		if (append_range(options, dft_ports))
			return (-1);
	if (options->scanflag == 0)
		options->scanflag = 0x1; // 1 when all flags active
	return (0);
}

static void		print_summary(t_opt *options)
{
	t_list		*tmp_ports = options->ports;
	t_list		*tmp_ips = options->ips;
	char		*flagstr[7] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP", 0};
	
	printf("IP(s) :");
	while (tmp_ips)
	{
		printf(" %s", inet_ntoa(((struct sockaddr_in*)tmp_ips->content)->sin_addr));
		tmp_ips = tmp_ips->next;
		(tmp_ips) ? printf(",") : printf("\n");
	}
	printf("Ports : ");
	while (tmp_ports)
	{
		printf("%d-%d", ((t_range*)(tmp_ports->content))->start, ((t_range*)(tmp_ports->content))->end);
		tmp_ports = tmp_ports->next;
		(tmp_ports) ? printf(",") : printf("\n");
	}
	printf("Threads : %d\n", options->threads);
	printf("Packets types :");
	for (int i = 0; i < 6; i++)
	{
		((options->scanflag >> (i + 1)) & 1) ? printf(" %s", flagstr[i]) : 0;
		(i < 5) ? printf(",") : printf("\n");
	}
}

int     nmap_optloop(t_opt *options, int nargs, char *const args[])
{
    char    opt = 0;
    int     optind = 1;
	int		ret = 0;

    while (ret == 0 && optind < nargs && (opt = nmap_getopt(nargs, args, &optind)))
    {
        switch(opt)
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
			if (ret)
				return (-1);
        }
        optind++;
    }
	if (set_defaults(options))
		return (-1);
	print_summary(options);
	return (0);
}