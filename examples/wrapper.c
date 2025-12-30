/**
 * C wrapper for FFI integration with the network stack.
 *
 * Makefile snippet (pkg-config compatible):
 *
 *   CFLAGS  = -I$(SHARDNET_ROOT)/include -Wall -Wextra
 *   LDFLAGS = -L$(SHARDNET_ROOT)/lib -lustack -lev
 *
 *   %.o: %.c
 *       $(CC) $(CFLAGS) -c $< -o $@
 *
 *   myapp: main.o
 *       $(CC) $^ $(LDFLAGS) -o $@
 */

#include <ev.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

/* Global state for cleanup */
static struct ev_loop *g_loop = NULL;
static int g_tun_fd = -1;
static int g_sock_fd = -1;

/**
 * Cleanup resources registered with atexit().
 */
static void cleanup(void) {
    if (g_tun_fd >= 0) {
        close(g_tun_fd);
        g_tun_fd = -1;
    }
    if (g_sock_fd >= 0) {
        close(g_sock_fd);
        g_sock_fd = -1;
    }
    if (g_loop != NULL) {
        ev_loop_destroy(g_loop);
        g_loop = NULL;
    }
}

void* my_ev_default_loop(void) {
    void* loop = ev_default_loop(0);
    if (loop == NULL) {
        fprintf(stderr, "ev_default_loop failed\n");
        return NULL;
    }
    g_loop = loop;
    return loop;
}

void my_ev_io_init(ev_io* w, void (*cb)(struct ev_loop *loop, ev_io *w, int revents), int fd, int events) {
    if (w == NULL || cb == NULL) {
        fprintf(stderr, "my_ev_io_init: NULL argument\n");
        return;
    }
    ev_io_init(w, cb, fd, events);
}

void my_ev_timer_init(ev_timer* w, void (*cb)(struct ev_loop *loop, ev_timer *w, int revents), double after, double repeat) {
    if (w == NULL || cb == NULL) {
        fprintf(stderr, "my_ev_timer_init: NULL argument\n");
        return;
    }
    ev_timer_init(w, cb, after, repeat);
}

void my_ev_io_start(void* loop, ev_io* w) {
    if (loop == NULL || w == NULL) {
        fprintf(stderr, "my_ev_io_start: NULL argument\n");
        return;
    }
    ev_io_start(loop, w);
}

void my_ev_timer_start(void* loop, ev_timer* w) {
    if (loop == NULL || w == NULL) {
        fprintf(stderr, "my_ev_timer_start: NULL argument\n");
        return;
    }
    ev_timer_start(loop, w);
}

void my_ev_io_stop(void* loop, ev_io* w) {
    if (loop == NULL || w == NULL) return;
    ev_io_stop(loop, w);
}

void my_ev_timer_stop(void* loop, ev_timer* w) {
    if (loop == NULL || w == NULL) return;
    ev_timer_stop(loop, w);
}

void my_ev_run(void* loop) {
    if (loop == NULL) {
        fprintf(stderr, "my_ev_run: NULL loop\n");
        return;
    }
    ev_run(loop, 0);
}

void my_ev_break(void* loop) {
    if (loop == NULL) return;
    ev_break(loop, EVBREAK_ALL);
}

int my_tuntap_init(int fd, const char* name) {
    if (fd < 0 || name == NULL) {
        return -EINVAL;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    /* SAFETY: strncpy with IFNAMSIZ ensures no buffer overflow.
     * The name parameter comes from user input and must be validated. */
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    int rc = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (rc < 0) {
        return -errno;
    }

    g_tun_fd = fd;
    return 0;
}

int my_set_if_up(const char* name) {
    if (name == NULL) {
        return -EINVAL;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -errno;
    }
    g_sock_fd = sockfd;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    /* SAFETY: strncpy bounded by IFNAMSIZ prevents overflow. */
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        int err = errno;
        close(sockfd);
        g_sock_fd = -1;
        return -err;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        int err = errno;
        close(sockfd);
        g_sock_fd = -1;
        return -err;
    }

    close(sockfd);
    g_sock_fd = -1;
    return 0;
}

int my_set_if_addr(const char* name, const char* addr) {
    if (name == NULL || addr == NULL) {
        return -EINVAL;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -errno;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    /* SAFETY: strncpy bounded by IFNAMSIZ prevents overflow. */
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    /* SAFETY: The sockaddr_in cast is safe because ifr_addr is a
     * sockaddr which has the same initial layout as sockaddr_in. */
    struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
    sin->sin_family = AF_INET;

    if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1) {
        close(sockfd);
        return -EINVAL;
    }

    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        int err = errno;
        close(sockfd);
        return -err;
    }

    /* Set netmask to /24 by default */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    sin = (struct sockaddr_in*)&ifr.ifr_netmask;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, "255.255.255.0", &sin->sin_addr) != 1) {
        close(sockfd);
        return -EINVAL;
    }

    int rc = ioctl(sockfd, SIOCSIFNETMASK, &ifr);
    close(sockfd);

    return (rc < 0) ? -errno : 0;
}

/**
 * Initialize wrapper and register cleanup handler.
 * Call this once at program start.
 */
int my_wrapper_init(void) {
    if (atexit(cleanup) != 0) {
        fprintf(stderr, "Failed to register cleanup handler\n");
        return -1;
    }
    return 0;
}
