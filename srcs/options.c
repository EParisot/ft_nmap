#include "ft_nmap.h"

void    bad_usage(t_opt *options, const char *arg, int context);        /* Handle error on parsing argument and quit gracefully */

void    read_ipaddr(t_opt *options, char *const args[], int *optind);   /* Treat the --ip argument */
void    fread_ipaddr(t_opt *options, char *const args[], int *optind);  /* Treat the --file argument */
void    read_speedup();                                                 /* Treat the --speedup argument */
void    read_scantypes();                                               /* Treat the --scan argument */

char    nmap_getopt(int nargs, char *const args[], int *optind);        /* Detect option to be treated and how to parse next argument */
int     nmap_optloop(t_opt *options, int nargs, char *const args[]);    /* Iterate through argv to parse arguments from command line */

void    bad_usage(t_opt *options, const char *arg, int context)
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

    dprintf(2, "argument error: %s, context %d\n", arg, context);
    //free_data(options);
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
}

int     nmap_optloop(t_opt *options, int nargs, char *const args[])
{
    char    opt = 0;
    int     optind = 0;

    while ((opt = nmap_getopt(nargs, args, &optind)))
    {
        switch(opt)
        {
            case 'h':
            bad_usage(options, NULL, 0);
            case 'p':
            // placeholder for port func
            case 'i':
            read_ipaddr(options, args, &optind);
            case 'f':
            fread_ipaddr(options, args, &optind);
            case 'v':
            read_speedup();
            case 's':
            read_scantypes();
        }
        optind++;
    }
}