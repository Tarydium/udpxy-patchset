/* @(#) basic http authorization routines
 *
 * Copyright 2008-2011 Pavel V. Cherenkov (pcherenkov@gmail.com) (pcherenkov@gmail.com)
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

#ifndef UDPXY_AUTH_H
#define UDPXY_AUTH_H

#ifdef __cpluspplus
    extern "C" {
#endif

#include <string.h>  /* size_t */

extern void base64_init(void);
extern int read_authfile(const char *fname);
extern int parse_auth( const char *src, size_t srclen);

#ifdef __cpluspplus
}
#endif

#endif  /* UDPXY_AUTH_H */

/* EOF */
