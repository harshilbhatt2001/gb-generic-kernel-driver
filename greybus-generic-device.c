// SPDX-License-Identifier: GPL-2.0
/*
 * GB_DEV Linux Driver for Greybus
 *
 * Copyright (c) 2024 Harshil Bhatt <harshilbhatt2001@gmail.com>
 */

#include <linux/greybus.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/printk.h>
#include <linux/workqueue.h>

#define DEFAULT_GREYBUS_DEVICE_IP_ADDRESS "192.168.0.103"
#define DEFAULT_GREYBUS_DEVICE_PORT 4242

struct gb_device {
  struct socket *sock;        // Wi-Fi socket for communication
  struct work_struct tx_work; // Work for handling outgoing messages
  struct work_struct rx_work; // Work for handling incoming messages
  struct greybus_host_device *gb_hd;
};

static struct gb_device *gb_dev;

/* Module parameters */
static char *gb_dev_ip = DEFAULT_GREYBUS_DEVICE_IP_ADDRESS;
static int gb_dev_port = DEFAULT_GREYBUS_DEVICE_PORT;

module_param(gb_dev_ip, charp, 0644);
MODULE_PARM_DESC(gb_dev_ip, "IP address of the greybus device");
module_param(gb_dev_port, int, 0644);
MODULE_PARM_DESC(gb_dev_port, "Wi-Fi port of the greybus device");

/* Function to send a message */
static int gb_dev_send_message(struct gb_device *dev, const u8 *data,
                               size_t len) {
  struct msghdr msg_hdr = {0};
  struct kvec iov = {
      .iov_base = (u8 *)data,
      .iov_len = len,
  };
  int ret;

  ret = kernel_sendmsg(dev->sock, &msg_hdr, &iov, 1, len);
  if (ret < 0) {
    pr_err("GB_DEV: Failed to send message (%d)\n", ret);
  } else {
    pr_info("GB_DEV: Sent %zu bytes in hex format\n", len);
    print_hex_dump(KERN_INFO, "GB_DEV: Hex Dump: ", DUMP_PREFIX_NONE, 16, 1,
                   data, len, true);
  }

  return ret;
}

/* Work function for receiving messages */
static void gb_dev_rx_work(struct work_struct *work) {
  struct msghdr msg_hdr = {0};
  struct kvec iov;
  char buf[512];
  int ret;

  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);

  ret =
      kernel_recvmsg(gb_dev->sock, &msg_hdr, &iov, 1, sizeof(buf), MSG_WAITALL);
  if (ret < 0) {
    pr_err("GB_DEV: Failed to receive message (%d)\n", ret);
    return;
  }

  pr_info("GB_DEV: Received message: %.*s\n", ret, buf);

  /* Process the Greybus message (mockup) */
}

/* Driver probe function */
static int gb_dev_probe(void) {
  struct sockaddr_in addr;
  int ret;

  pr_info("GB_DEV: Initializing driver\n");

  if (!gb_dev_ip) {
    pr_err(
        "GB_DEV: IP address not provided. Set gb_dev_ip module parameter.\n");
    return -EINVAL;
  }

  gb_dev = kzalloc(sizeof(*gb_dev), GFP_KERNEL);
  if (!gb_dev)
    return -ENOMEM;

  /* Create a socket for communication */
  ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
                         &gb_dev->sock);

  if (ret) {
    pr_err("GB_DEV: Failed to create socket (%d)\n", ret);
    goto err_free;
  }
  pr_info("GB_DEV: Socket created\n");

  /* Configure the server address */
  addr.sin_family = AF_INET;
  addr.sin_port = htons(gb_dev_port);
  addr.sin_addr.s_addr = in_aton(gb_dev_ip);

  /* Connect to the GB_DEV */
  ret = kernel_connect(gb_dev->sock, (struct sockaddr *)&addr, sizeof(addr), 0);
  if (ret) {
    pr_err("GB_DEV: Failed to connect to GB_DEV (%d)\n", ret);
    goto err_sock;
  }
  pr_info("GB_DEV: Connected to GB_DEV\n");

  INIT_WORK(&gb_dev->rx_work, gb_dev_rx_work);

  u8 gb_ping[] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  gb_dev_send_message(gb_dev, gb_ping, sizeof(gb_ping));

  pr_info("GB_DEV: Driver initialized successfully\n");
  return 0;

err_sock:
  sock_release(gb_dev->sock);
err_free:
  kfree(gb_dev);
  return ret;
}

/* Driver remove function */
static void gb_dev_remove(void) {
  pr_info("GB_DEV: Removing driver\n");

  if (gb_dev) {
    if (gb_dev->sock)
      sock_release(gb_dev->sock);
    kfree(gb_dev);
  }

  pr_info("GB_DEV: Driver removed\n");
}

/* Module initialization and exit */
static int __init gb_dev_init(void) { return gb_dev_probe(); }

static void __exit gb_dev_exit(void) { gb_dev_remove(); }

module_init(gb_dev_init);
module_exit(gb_dev_exit);

MODULE_DESCRIPTION("Generic greybus driver over Wi-Fi");
MODULE_AUTHOR("Harshil Bhatt <harshilbhatt2001@gmail.com>");
MODULE_LICENSE("GPL");
