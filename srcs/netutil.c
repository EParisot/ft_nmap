/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   netutils.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: maabou-h <maabou-h@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/05 23:09:42 by maabou-h          #+#    #+#             */
/*   Updated: 2020/09/05 23:11:02 by maabou-h         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_nmap.h"

uint8_t                *getlocalhost(t_opt *opt)
{
    struct ifaddrs  *id;
    struct ifaddrs  *ifa;
    char         *str;

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
    return (uint8_t*)str;
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

static void set_addr_info_struct(struct addrinfo *hints)
{
	ft_memset(hints, 0, sizeof(struct addrinfo));
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_DGRAM;
	hints->ai_flags = AI_PASSIVE | AI_CANONNAME;
	hints->ai_protocol = 0;
	hints->ai_canonname = NULL;
	hints->ai_addr = NULL;
	hints->ai_next = NULL;
}

static void free_addr_info(struct addrinfo *result)
{
	struct addrinfo *tmp;

	while (result)
	{
		tmp = result;
		result = result->ai_next;
		free(tmp->ai_canonname);
		free(tmp);
	}
}

static int dns_err(char *address, struct addrinfo *hints, struct addrinfo **result)
{
	int err;

	err = 0;
	if ((err = getaddrinfo(address, NULL, hints, result)) != 0)
	{
		if (err != -5 && err != -2)
			fprintf(stderr, \
	"ft_nmap: %s: Temporary failure in name resolution\n", address);
		else if (err == -5)
			fprintf(stderr, \
	"ft_nmap: %s: No address associated with hostname!\n", address);
		else if (err == -2)
			fprintf(stderr, "ft_nmap: %s: Name or service not known\n",\
				address);
		return (-1);
	}
	return (0);
}

static int dns_get(struct addrinfo *result, char *str_addr)
{
	struct sockaddr_in	*addr_in;

	if (result->ai_addr->sa_family == AF_INET)
	{
		addr_in = (struct sockaddr_in *)result->ai_addr;
		inet_ntop(AF_INET, &(addr_in->sin_addr), str_addr, INET_ADDRSTRLEN);
	}
	else if (result->ai_addr->sa_family == AF_INET6)
	{
		fprintf(stderr, "ft_nmap: IPV6 Not Implemented\n");
		return (-1);
	}
	return (0);
}

int dns_lookup(char *address, char *target)
{
	struct addrinfo hints;
	struct addrinfo *result;

	result = NULL;
	set_addr_info_struct(&hints);
	if (dns_err(address, &hints, &result) == -1)
	{
		return (-1);
	}
	if (result)
	{
		if (dns_get(result, target))
		{
			return (-1);
		}
	}
	free_addr_info(result);
	return (0);
}