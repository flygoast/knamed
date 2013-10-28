#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <linux/netlink.h>

#include "kn_connector.h"
#include "kn_conf.h"


#define KNAMED_VERSION  "0.0.1"


#define MAX_EVENTS      1


#define KNAMED_START    KN_CN_VAL_START
#define KNAMED_STOP     KN_CN_VAL_STOP
#define KNAMED_RELOAD   KN_CN_VAL_RELOAD


static int    knamed_action = KNAMED_START;
static char  *conf_file;


static struct option const long_options[] = {
    {"config",  required_argument, NULL, 'c'},
    {"help",    no_argument,       NULL, 'h'},
    {"version", no_argument,       NULL, 'v'},
    {NULL, 0, NULL, 0}
};


int netlink_send(int sock, struct kn_cn_msg *msg)
{
    int                ret = 0;
    char               buf[NETLINK_PAYLOAD + sizeof(struct nlmsghdr)];
    unsigned int       size;
    struct nlmsghdr   *nlh;
    struct kn_cn_msg  *m;

    size = NLMSG_SPACE(sizeof(struct kn_cn_msg) + msg->len);

    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_type = NLMSG_DONE;
    nlh->nlmsg_len = NLMSG_LENGTH(size - sizeof(*nlh));
    nlh->nlmsg_flags = 0;

    m = NLMSG_DATA(nlh);
    memcpy(m, msg, sizeof(*m) + msg->len);

    ret = send(sock, nlh, size, 0);
    if (ret == -1) {
        fprintf(stderr, "send netlink message failed: %s\n", strerror(errno));
    }

    return ret;
}


static int netlink_send_ctrl(int sock, int action)
{
    struct kn_cn_msg msg;

    msg.id.idx = KN_CN_IDX_CTL;
    msg.id.val = action;
    msg.len = 0;

    return netlink_send(sock, &msg);
}


static void print_info(void)
{
    printf("knamed: knamed control utility\n"
           "Version: %s\n"
           "Copyright (c) flygoast, flygoast@126.com\n",
           KNAMED_VERSION);
}


static void usage(int status)
{
    if (status != EXIT_SUCCESS) {
        fprintf(stderr, "Try `knamed --help' for more information.\n");

    } else {
        printf("Usage:knamed [--config=<conf_file> | -c] [start|stop|reload]\n"
               "             [--version | -v]\n"
               "             [--help | -h]\n");
    }
}


static void parse_options(int argc, char **argv)
{
    int c;

    while ((c = getopt_long(argc, argv, "c:hv", long_options, NULL)) != -1) {
        switch (c) {
        case 'c':
            conf_file = optarg;
            break;

        case 'h':
            usage(EXIT_SUCCESS);
            exit(EXIT_SUCCESS);

        case 'v':
            print_info();
            exit(EXIT_SUCCESS);

        default:
            usage(EXIT_FAILURE);
            exit(1);
        }
    }

    if (optind + 1 == argc) {
        if (!strcasecmp(argv[optind], "stop")) {
            knamed_action = KNAMED_STOP;

        } else if (!strcasecmp(argv[optind], "start")) {
            knamed_action = KNAMED_START;

        } else if (!strcasecmp(argv[optind], "reload")) {
            knamed_action = KNAMED_RELOAD;

        } else {
            usage(EXIT_FAILURE); 
            exit(1);
        }

    } else if (optind == argc) {
        knamed_action = KNAMED_START;

    } else {
        usage(EXIT_FAILURE);
        exit(1);
    }
}


int main(int argc, char **argv)
{
    int                  ret, flags;
    int                  sock, epfd, i, n;
    struct sockaddr_nl   local;
    struct epoll_event   events[MAX_EVENTS];
    size_t               len;
    char                 buf[NETLINK_PAYLOAD];
    struct nlmsghdr     *nlh;
    struct kn_cn_msg    *msg;

    parse_options(argc, argv);

    sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KNAMED);
    if (sock == -1) {
        fprintf(stderr, "create netlink socket failed: %s\n", strerror(errno));
        ret = 1;
        goto out;
    }

    flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        fprintf(stderr, "fcntl, F_GETFL failed: %s\n", strerror(errno));
        ret = 1;
        goto close_sock;
    }

    ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    if (ret == -1) {
        fprintf(stderr, "fcntl, F_SETFL failed: %s\n", strerror(errno));
        ret = 1;
        goto close_sock;
    }

    local.nl_family = AF_NETLINK; 
    local.nl_groups = NETLINK_KNAMED_GRP;
    local.nl_pid = 0;

    ret = bind(sock, (struct sockaddr *)&local, sizeof(local));
    if (ret == -1) {
        fprintf(stderr, "bind netlink group failed: %s\n", strerror(errno));
        ret = 1;
        goto close_sock;
    }

    epfd = epoll_create(1024);
    if (epfd == -1) {
        fprintf(stderr, "epoll_create failed: %s\n", strerror(errno));
        ret = 1;
        goto close_sock;
    }

    netlink_send_ctrl(sock, knamed_action);

    for ( ;; ) {
        n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }

            fprintf(stderr, "epoll_wait failed: %s\n", strerror(errno));
            ret = 1;
            goto close_epoll;
        }

        for (i = 0; i < n; i++) {
            if (events[i].data.fd == sock) {
                len = recv(sock, buf, sizeof(buf), 0);
                if (len == -1) {
                    fprintf(stderr, "recv socket failed: %s\n",
                            strerror(errno));
                    continue;
                }

                nlh = (struct nlmsghdr *)buf;

                switch (nlh->nlmsg_type) {
                case NLMSG_ERROR:
                    fprintf(stderr, "netlink recv failed: %s\n",
                            strerror(errno));
                    break;

                case NLMSG_DONE:
                    msg = (struct kn_cn_msg *)NLMSG_DATA(nlh);

                    switch (msg->id.idx) {
                    default:
                        printf("IDX: %d, VAL: %d\n", msg->id.idx, msg->id.val);
                        ret = 0;
                        goto close_epoll;
                    }

                    break;

                default:
                    break;
                }
            }
        }
    }

    ret = 0;
    
close_epoll:

    close(epfd);

close_sock:

    close(sock);

out:

    exit(ret);
}
