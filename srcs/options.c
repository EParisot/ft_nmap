#include "../includes/ft_nmap.h"

int	    bad_usage(const char *arg, int context)
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

static int		append_range(t_opt *options, char **dash_tab)
{
	(void)options;
	for (int i = 0; dash_tab[i]; i++)
		printf("%s ", dash_tab[i]);
	printf("\n");
	return (0);
}

static int		read_ports(t_opt *options, char *const args[], int *optind)
{
	(void)options;
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

int		fread_ipaddr(t_opt *options, char *const args[], int *optind)
{
	(void)options;
	printf("%s\n", args[*optind + 1]);
	(*optind)++;
	return (0);
}

int		read_ipaddr(t_opt *options, char *const args[], int *optind)
{
	(void)options;
	printf("%s\n", args[*optind + 1]);
	(*optind)++;
	return (0);
}

int		read_speedup(t_opt *options, char *const args[], int *optind)
{
	(void)options;
	printf("%s\n", args[*optind + 1]);
	(*optind)++;
	return (0);
}

int		read_scantypes(t_opt *options, char *const args[], int *optind)
{
	(void)options;
	printf("%s\n", args[*optind + 1]);
	(*optind)++;
	return (0);
}

char    nmap_getopt(int nargs, char *const args[], int *optind) // pas finie
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
	return (0);
}