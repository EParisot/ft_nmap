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


t_ping_pkt	*build_pkt()
{
	t_ping_pkt			*pkt;
	long unsigned int	i;

	i = 0;
	if ((pkt = (t_ping_pkt *)malloc(sizeof(t_ping_pkt))) == NULL)
		return (NULL);
	ft_memset(pkt, 0, sizeof(t_ping_pkt));
	pkt->header.type = ICMP_ECHO;
	pkt->header.un.echo.id = getpid();
	while (i < sizeof(pkt->msg) - 1)
		pkt->msg[i++] = 42;
	pkt->msg[i] = 0;
	pkt->header.un.echo.sequence = 0;
	pkt->header.un.echo.sequence = 0;
	pkt->header.checksum = csum((unsigned short*)pkt, sizeof(*pkt));
	return (pkt);
}

struct msghdr *build_msg(struct sockaddr *addr_struct)
{
	struct msghdr	*msg;
	struct iovec	*iov;
	char			*buffer;

	if ((msg = (struct msghdr *)malloc(sizeof(struct msghdr))) == NULL)
		return (NULL);
	if ((iov = (struct iovec *)malloc(sizeof(struct iovec))) == NULL)
		return (NULL);
	if ((buffer = malloc(BUFFER_MAX_SIZE)) == NULL)
		return (NULL);
	ft_memset(msg, 0, sizeof(struct msghdr));
	ft_memset(iov, 0, sizeof(struct iovec));
	ft_memset(buffer, 0, BUFFER_MAX_SIZE);
	iov->iov_base = buffer;
	iov->iov_len = BUFFER_MAX_SIZE;
	msg->msg_iov = iov;
	msg->msg_iovlen = 1;
	msg->msg_name = addr_struct;
	msg->msg_namelen = sizeof(struct sockaddr);
	return (msg);
}

int ping_ip(struct sockaddr_in *ip) 
{
	t_ping_pkt	*pkt;
	int ping_socket;
	struct timeval tv_out;
	int ttl_val = TTL_VAL;
	tv_out.tv_sec = PING_TIMEOUT;
	tv_out.tv_usec = 0;

	if ((pkt = build_pkt()) == NULL)
		return (-1);
	ip->sin_family = AF_INET;
	if ((ping_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
		return (-1);
	if (setsockopt(ping_socket, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)))
		return (-1);
	if (setsockopt(ping_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out)) != 0)
		return (-1);
	if (sendto(ping_socket, pkt, sizeof(t_ping_pkt), 0, (struct sockaddr *)ip, sizeof(struct sockaddr)) < 0)
	{
		free(pkt);
		close(ping_socket);
		return (-1);
	}
	struct msghdr *msg = build_msg((struct sockaddr *)ip);
	int received_size = recvmsg(ping_socket, msg, 0);
	free(pkt);
	free(msg->msg_iov->iov_base);
	free(msg->msg_iov);
	free(msg);
	close(ping_socket);
	if (received_size == 0)
		return (-1);
	return (0);
}