#ifndef PASTORAL_BPF_SHIM_H
#define PASTORAL_BPF_SHIM_H

#include <net/bpf.h>
#include <sys/ioctl.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Expose BPF ioctl constants as C constants so Swift can use them
// without needing the _IOW/_IOR macros (which aren't available in
// the SPM C module compilation context).
static const unsigned long pastoral_BIOCSETIF = BIOCSETIF;
static const unsigned long pastoral_BIOCGBLEN = BIOCGBLEN;
static const unsigned long pastoral_BIOCIMMEDIATE = BIOCIMMEDIATE;
static const unsigned long pastoral_BIOCSHDRCMPLT = BIOCSHDRCMPLT;
static const size_t pastoral_bpf_hdr_size = sizeof(struct bpf_hdr);

// Wrappers for ioctl (variadic, unavailable in Swift).
static inline int pastoral_ioctl_ulong(int fd, unsigned long req, unsigned long *val) {
    return ioctl(fd, req, val);
}
static inline int pastoral_ioctl_ifname(int fd, unsigned long req, const char *ifname) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    return ioctl(fd, req, &ifr);
}

// Extract MAC address bytes from a sockaddr_dl. Returns 0 on success,
// -1 if the link address is not 6 bytes.
static inline int pastoral_extract_mac(const struct sockaddr_dl *sdl, unsigned char *out_mac) {
    if (sdl->sdl_alen != 6) return -1;
    const void *addr = LLADDR(sdl);
    memcpy(out_mac, addr, 6);
    return 0;
}

// Extract IPv4 bytes from a sockaddr_in. Returns 0 on success.
static inline int pastoral_extract_ipv4(const struct sockaddr_in *sin, unsigned char *out_ip) {
    unsigned int addr = sin->sin_addr.s_addr;
    out_ip[0] = addr & 0xFF;
    out_ip[1] = (addr >> 8) & 0xFF;
    out_ip[2] = (addr >> 16) & 0xFF;
    out_ip[3] = (addr >> 24) & 0xFF;
    return 0;
}

// Toggle IFF_PROMISC on a named interface. Reads the live flags with
// SIOCGIFFLAGS first and flips ONLY the promisc bit, so the interface
// stays IFF_UP while the hound listens (writing a stale/zeroed flag word
// would tear down the link). Used by the Wi-Fi key hound so EAPOL
// traffic between OTHER stations reaches us.
static inline int pastoral_set_promisc(const char *ifname, int on) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) { close(fd); return -1; }
    if (on) ifr.ifr_flags |= (unsigned short)IFF_PROMISC;
    else    ifr.ifr_flags &= (unsigned short)~IFF_PROMISC;
    int r = ioctl(fd, SIOCSIFFLAGS, &ifr);
    close(fd);
    return r;
}

#endif
