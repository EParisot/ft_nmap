#include "../includes/ft_nmap.h"

char                *getlocalhost(t_opt *opt)
{
    struct ifaddrs  *id;
    struct ifaddrs  *ifa;
    char            *str;

    str = NULL;
    if (getifaddrs(&id) == -1)
        return NULL;
    for (ifa = id; ifa != NULL; ifa = ifa->ifa_next)
    {
        if((ifa->ifa_addr != NULL) && (ft_strcmp(ifa->ifa_name, opt->dev->device) == 0) && (ifa->ifa_addr->sa_family == AF_INET))
        {
               str = ft_strdup(inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));
               break ;
        }
    }
    freeifaddrs(id);
    return str;
}

unsigned short csum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1)
    {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1)
    {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum>>16);
	answer = (short)~sum;
	return(answer);
}
