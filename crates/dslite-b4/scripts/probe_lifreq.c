/*
 * probe_lifreq.c verify the layout of `struct lifreq` and the encoded
 * SIOCSLIF* ioctl numbers on the host illumos distribution.
 *
 * The Rust daemon mirrors `struct lifreq` in src/tunnel/illumos.rs and
 * pins its size with a `const _: () = assert!(...)`. The values that
 * assertion checks against come from this probe. Re-run this whenever
 * the assertion fails.
 *
 * Build & run:
 *     gcc -m64 -o probe_lifreq probe_lifreq.c && ./probe_lifreq
 *
 * Output captured on OmniOS r151054 on 2026-04-29:
 *
 *     sizeof(struct lifreq)    = 376 (0x178)
 *     offsetof(lifr_lifru)     = 40
 *     offsetof(lifr_type)      = 36
 *     sizeof(sockaddr_storage) = 256
 *     SIOCSLIFADDR    = 0x80786970
 *     SIOCSLIFDSTADDR = 0x80786972
 *     SIOCSLIFNETMASK = 0x8078697e
 *     SIOCSLIFFLAGS   = 0x80786974
 *     SIOCGLIFFLAGS   = 0xc0786975
 */

#include <net/if.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/sockio.h>

int main(void) {
    printf("sizeof(struct lifreq)    = %zu (0x%zx)\n", sizeof(struct lifreq),
           sizeof(struct lifreq));
    printf("offsetof(lifr_lifru)     = %zu\n",
           offsetof(struct lifreq, lifr_lifru));
    printf("offsetof(lifr_type)      = %zu\n",
           offsetof(struct lifreq, lifr_type));
    printf("sizeof(sockaddr_storage) = %zu\n", sizeof(struct sockaddr_storage));
    printf("SIOCSLIFADDR    = 0x%08x\n", SIOCSLIFADDR);
    printf("SIOCSLIFDSTADDR = 0x%08x\n", SIOCSLIFDSTADDR);
    printf("SIOCSLIFNETMASK = 0x%08x\n", SIOCSLIFNETMASK);
    printf("SIOCSLIFFLAGS   = 0x%08x\n", SIOCSLIFFLAGS);
    printf("SIOCGLIFFLAGS   = 0x%08x\n", SIOCGLIFFLAGS);
    return 0;
}
