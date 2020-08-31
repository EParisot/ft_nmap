/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sdincbud <sdincbud@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/16 17:17:04 by maabou-h          #+#    #+#             */
/*   Updated: 2019/06/24 10:07:29 by sdincbud         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <unistd.h>
#include <stdlib.h>
#include "libft.h"

#define BUFF_SIZE 4096

static char	*ft_join(char *s1, char *s2, size_t n)
{
	char	*new;
	size_t	i;
	size_t	pos;

	if (!(new = ft_memalloc((sizeof(char) * (ft_strlen(s1) + n + 1)))))
		return (NULL);
	i = 0;
	pos = 0;
	while (s1[i])
		new[pos++] = s1[i++];
	i = 0;
	while (n-- && s2[i])
		new[pos++] = s2[i++];
	new[pos] = '\0';
	return (new);
}

static int	ft_buf(char **line, char **buf)
{
	char	*tmp;

	tmp = *line;
	*line = ft_join(tmp, *buf, (ft_strlen(*buf) -
				ft_strlen(ft_strchr(*buf, '\n'))));
	free(tmp);
	tmp = *buf;
	*buf = ft_strdup(ft_strchr(*buf, '\n'));
	free(tmp);
	if (*buf)
	{
		tmp = *buf;
		*buf = ft_strdup(*buf + 1);
		free(tmp);
		return (1);
	}
	return (0);
}

int			get_next_line(const int fd, char **line)
{
	static char	*buf = NULL;
	int			ret;

	if (fd < 0 || !line || fd > 4894 || !(*line = ft_strnew(0)))
		return (-1);
	ret = 1;
	while (ret != -1)
	{
		if (buf == NULL)
		{
			buf = ft_strnew(BUFF_SIZE);
			if ((ret = read(fd, buf, BUFF_SIZE)) == -1)
				return (-1);
		}
		if (ft_buf(line, &buf))
			return (1);
		if (ret == 0)
		{
			if (!*line[0])
				return (0);
			return (1);
		}
	}
	return (-1);
}