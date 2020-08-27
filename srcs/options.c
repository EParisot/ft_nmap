#include "../includes/ft_nmap.h"

int	    bad_usage(t_opt *options, const char *arg, int context)
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

    fprintf(stderr, "argument error: %s, context %d\n", arg, context);
	return (-1);
}

int		read_ports(t_opt *options, char *const args[], int *optind)
{

	return (0);
}

char    nmap_getopt(int nargs, char *const args[], int *optind) // pas finie
{
    const char  *target = args[*optind];

    if (!ft_strcmp("--help", target))
    {
        return 'h';
    }
    else if (!ft_strcmp("--ports", target))
    {
        return 'p';
    }
    else if (!ft_strcmp("--ip", target))
    {
        return 'i';
    }
    else if (!ft_strcmp("--file", target))
    {
        return 'f';
    }
    else if (!ft_strcmp("--speedup", target))
    {
        return 'v';
    }
    else if (!ft_strcmp("--scan", target))
    {
        return 's';
    }
	return (-1);
}

int     nmap_optloop(t_opt *options, int nargs, char *const args[])
{
    char    opt = 0;
    int     optind = 0;
	int		ret = 0;

    while ((opt = nmap_getopt(nargs, args, &optind)))
    {
        switch(opt)
        {
            case 'h':
            	ret = bad_usage(options, NULL, 0);
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
            	ret = read_speedup();
			break;
            case 's':
            	ret = read_scantypes();
			break;
			if (ret)
				return (-1);
        }
        optind++;
    }
	return (0);
}