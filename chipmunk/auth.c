/* @(#) basic HTTP authentication.
 *
 *  Copyright 2008-2011 Pavel V. Cherenkov (pcherenkov@gmail.com)
 *
 *  This file is part of udpxy.
 *
 *  udpxy is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  udpxy is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with udpxy.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "auth.h"

#define MAXLINE  4096
#define MAXUSERS 1024      /* ..todo!!! allow dynamical growing! */

static char **valid_users;
static size_t valid_users_count;  /* ..up to MAXUSERS */


/*
 *  base64 decoding routines are adopted from here:
 *     http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
 */

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char decoding_table[256];

void base64_init(void)
{
    int i;
    for (i = 0; i < 0x40; i++)
        decoding_table[ (size_t) encoding_table[i] ] = i;
}

size_t base64_decode(const char *data,
                    size_t input_length,
                    char *decoded_data,
                    size_t decoded_length) {
    size_t i, j, output_length;

    if (input_length % 4 != 0) return 0;

    output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') output_length--;
    if (data[input_length - 2] == '=') output_length--;

    if (output_length > decoded_length)
        return 0;   /* ..destination buffer is too small */

    for (i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : ((uint32_t) decoding_table[(size_t) data[i++]]);
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : ((uint32_t) decoding_table[(size_t) data[i++]]);
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : ((uint32_t) decoding_table[(size_t) data[i++]]);
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : ((uint32_t) decoding_table[(size_t) data[i++]]);

        uint32_t triple = (sextet_a << 3 * 6)
                        + (sextet_b << 2 * 6)
                        + (sextet_c << 1 * 6)
                        + (sextet_d << 0 * 6);

        if (j < output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return output_length;
}


/* check presence of Basic HTTP Auth
 *
 * @param src          buffer with raw HTTP request
 * @param srclen       length of raw data
 *
 * @return 0 if authentication is successfully passed
 * @return 1 if request does not contain auth data
 * @return 2 if auth data has invalid format
 * @return 3 if username:password pair is wrong or unknown
 */
int
parse_auth( const char *src, size_t srclen)
{
    static const char PFX[] = "\r\nAuthorization: Basic ";
    const char *linestart;
    const char *datastart, *dataend;  /* ..data start, data end */
    char decoded[512];                /* ..should be enough for username:userpass string */
    size_t encoded_len, decoded_len;
    size_t n;

    if (!valid_users_count)
        return 0;

    linestart = strstr(src, PFX);
    if (!linestart)
        return 1;       /* ..request does not contain Basic HTTP Auth info */
    datastart = linestart + sizeof(PFX) - 1;
    if (datastart >= src + srclen)
        return 1;
    dataend = memchr(datastart, '\r', srclen - (size_t)(datastart - linestart));
    if (!dataend || dataend >= src + srclen)
        return 2;       /* ..auth data has invalid format */
    encoded_len = (size_t)(dataend - datastart);
    decoded_len = base64_decode(datastart, encoded_len, decoded, sizeof(decoded));
    if (!decoded_len)
        return 2;       /* ..auth data has invalid format */

    for (n = 0; n < valid_users_count; n++) {
        const char *v = valid_users[n];
        if (!memcmp(v, decoded, decoded_len) && v[decoded_len] == '\0')
            return 0;   /* ..found! */
    }
    return 3;           /* ..not found! */
}


/*  read given file and parse lines into valid_users array
 *
 *  @param fname name of text file containing username:userpass pairs (one per line)
 *
 *  @return  0 ok
 *  @return -1 cannot open file
 *  @return -2 cannot allocate memory
 */
int
read_authfile( const char *fname )
{
    char line[MAXLINE];
    FILE *f = fopen(fname, "r");
    if (!f)
        return -1;

    if (!valid_users)
        valid_users = malloc(MAXUSERS * sizeof(char*));
    if (!valid_users)
        return -2;
    valid_users_count = 0;

    while( fgets(line, sizeof(line), f) ) {
        char *begin = line;
        char *end = line + strlen(line) - 1;
        /* strip trailing CR/LF, spaces and tabs.. */
        while (begin <= end && isspace(*end))
            *end-- = '\0';
        /* skip beginning spaces and tabs.. */
        while (begin <= end && isspace(*begin))
            begin++;
        /* skip empty lines and comments.. */
        if (begin > end || *begin == '#')
            continue;
        valid_users[valid_users_count++] = strdup(begin);
        if (valid_users_count == MAXUSERS)
            break;
    }
    fclose(f);
    return 0;
}

/* EOF */
