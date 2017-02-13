/*
 *    linotp-auth-pam - LinOTP PAM module
 *    Copyright (C) 2010 - 2017 KeyIdentity GmbH
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *     E-mail: linotp@keyidentity.com
 *     Contact: www.linotp.org
 *     Support: www.keyidentity.com
 */

#include <stdio.h>
#include <stdint.h>

#include "zeromem.h" // beinhaltet auch #include <errno.h> und <string.h>

#if !(defined(HAVE_MEMSET_S) && HAVE_MEMSET_S==1)
/* protect memset_s from compiler optimization */

// some compilers have support for: __attribute__((optimize("O0")))
int memset_s(void *s, size_t smax, int c, size_t n) {
    int err = 0;

    if (s == NULL) {
        return EINVAL;
    }
    if (smax > SIZE_MAX) {
        return E2BIG;
    }
    if (n > SIZE_MAX) {
        err = E2BIG;
        n = smax;
    }
    if (n > smax) {
        err = EOVERFLOW;
        n = smax;
    }

    volatile unsigned char *p = (unsigned char*)s;
    while (n-- > 0)
        *p++ = (unsigned char)c;

    return err;
}
#endif // HAVE_MEMSET_S


#if __SECURE_ZEROMEM==0
void secure_zeromem(void *b, size_t n) {
    volatile unsigned char *p = (unsigned char*)b;
    while (n-- > 0)
        *p++ = 0;
}
#endif
