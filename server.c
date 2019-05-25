#include <linux/netlink.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Protocol family, consistent in both kernel prog and user prog. */
#define MYPROTO NETLINK_USERSOCK
/* Multicast group, consistent in both kernel prog and user prog. */
#define MYMGRP 31

int open_netlink(void) {
  int sock;
  struct sockaddr_nl addr;
  int group = MYMGRP;

  sock = socket(AF_NETLINK, SOCK_RAW, MYPROTO);
  if (sock < 0) {
    printf("sock < 0.\n");
    return sock;
  }

  memset((void *)&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;
  addr.nl_pid = getpid();
  /* This doesn't work for some reason. See the setsockopt() below. */
  /* addr.nl_groups = MYMGRP; */

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    printf("bind < 0.\n");
    return -1;
  }

  /*
   * 270 is SOL_NETLINK. See
   * http://lxr.free-electrons.com/source/include/linux/socket.h?v=4.1#L314
   * and
   * http://stackoverflow.com/questions/17732044/
   */
  if (setsockopt(sock, 270, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) <
      0) {
    printf("setsockopt < 0\n");
    return -1;
  }

  return sock;
}

int read_event(int sock) {
  struct sockaddr_nl nladdr;
  struct msghdr msg;
  struct iovec iov;
  char buffer[65536];
  int ret;

  iov.iov_base = (void *)buffer;
  iov.iov_len = sizeof(buffer);
  msg.msg_name = (void *)&(nladdr);
  msg.msg_namelen = sizeof(nladdr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  printf("Ok, listening.\n");
  ret = recvmsg(sock, &msg, 0);
  if (ret < 0)
    printf("ret < 0.\n");
  else {
    char *message = NLMSG_DATA((struct nlmsghdr *)&buffer);
    if (strcmp(message, "kys") == 0) {
      printf("Shutting down server.");
      // If it wasn't clear - I'm gonna need to die. Excuse moa lol
      return 1;
    }

    char *payload = NLMSG_DATA((struct nlmsghdr *)&buffer);

    int pid = atoi(payload);

    printf("Received message payload: %s\n", payload);

    if (pid == 0) {
      printf("Received payload is not a number! not a possible PID.");
    } else {
      printf("Killing this process...");

      kill(pid, SIGKILL);
    }

    // Another day, another smile :)
    return 0;
  }
}

int main(int argc, char *argv[]) {
  int nls;

  nls = open_netlink();
  if (nls < 0)
    return nls;

  int shouldIDie = 0;
  while (!shouldIDie)
    shouldIDie = read_event(nls);

  return 0;
}
