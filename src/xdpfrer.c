#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/cdefs.h>
#include <time.h>
#include <net/if.h>
#include <argp.h>
#include <error.h>
#include <unistd.h>

#include "common.h"
#include "xdpfrer.skel.h"

#define ATTACH_INTERFACE "eth0"
#define REDIRECT_INTERFACE "eth0"

int main(void)
{
    struct xdpfrer_bpf *skel = xdpfrer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "%s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    int redirect_map_fd = bpf_map__fd(skel->maps.redirect_map);
    if (redirect_map_fd < 0) {
        fprintf(stderr, "Map not found\n");
        return EXIT_FAILURE;
    }

    struct bpf_devmap_val iface = { };
    int ifindex = if_nametoindex(REDIRECT_INTERFACE);
    if (!ifindex) {
	perror("if_nametoindex");
        return EXIT_FAILURE;
    }
    iface.ifindex = ifindex;

    iface.bpf_prog.fd = bpf_program__fd(skel->progs.prog_after_redirect);

    bpf_map_update_elem(redirect_map_fd, 0, &iface, 0);

    int prog_fd = bpf_program__fd(skel->progs.prog);

    ifindex = if_nametoindex(ATTACH_INTERFACE);
    if (!ifindex) {
        perror("if_nametoindex");
        return EXIT_FAILURE;
    }

    int ret = bpf_xdp_attach(ifindex, prog_fd, 1, NULL);
    if (ret < 0) {
        fprintf(stderr, "Failed to attach XDP program to iface %s\n", ATTACH_INTERFACE);
        return EXIT_FAILURE;
    }

    return 0;
}
