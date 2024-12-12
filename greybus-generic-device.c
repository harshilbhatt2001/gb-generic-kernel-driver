// SPDX-License-Identifier: GPL-2.0
/*
 * GB_DEV Linux Driver for Greybus
 *
 * Copyright (c) 2024 Harshil Bhatt <harshilbhatt2001@gmail.com>
 */

#include <linux/circ_buf.h>
#include <linux/crc-ccitt.h>
#include <linux/crc32.h>
#include <linux/greybus.h>
#include <linux/if_arp.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/workqueue.h>

#define DEFAULT_GREYBUS_DEVICE_IP_ADDRESS "192.168.0.103"
#define DEFAULT_GREYBUS_DEVICE_PORT 4242

#define RX_HDLC_PAYLOAD 256
#define CRC_LEN 2
#define MAX_RX_HDLC (1 + RX_HDLC_PAYLOAD + CRC_LEN)
#define TX_CIRC_BUF_SIZE 1024

#define ADDRESS_GREYBUS 0x01
#define ADDRESS_DBG 0x02
#define ADDRESS_CONTROL 0x03

#define HDLC_FRAME 0x7E
#define HDLC_ESC 0x7D
#define HDLC_XOR 0x20

#define CONTROL_SVC_START 0x01
#define CONTROL_SVC_STOP 0x02

/* The maximum number of CPorts supported by Greybus Host Device */
#define GB_MAX_CPORTS 32

/**
 * struct gb_device - Greybus device structure
 *
 * @gb_hd: greybus host device
 *
 * @sock: socket for Wi-Fi communication
 *
 * @tx_work: hdlc transmit work
 * @tx_producer_lock: hdlc transmit data producer lock. acquired when appending
 * data to buffer.
 * @tx_consumer_lock: hdlc transmit data consumer lock. acquired when sending
 * data over uart.
 * @tx_circ_buf: hdlc transmit circular buffer.
 * @tx_crc: hdlc transmit crc-ccitt fcs
 *
 * @rx_buffer_len: length of receive buffer filled.
 * @rx_buffer: hdlc frame receive buffer
 * @rx_in_esc: hdlc rx flag to indicate ESC frame
 */

struct gb_device {
  struct platform_device *pdev;

  struct gb_host_device *gb_hd;

  struct socket *sock;

  struct work_struct tx_work;
  spinlock_t tx_producer_lock;
  spinlock_t tx_consumer_lock;
  struct circ_buf tx_circ_buf;
  u16 tx_crc;

  u16 rx_buffer_len;
  bool rx_in_esc;
  u8 rx_buffer[MAX_RX_HDLC];
};

/**
 * struct hdlc_payload - Structure to represent part of HDCL frame payload data.
 *
 * @len: buffer length in bytes
 * @buf: payload buffer
 */
struct hdlc_payload {
  u16 len;
  void *buf;
};

/**
 * struct hdlc_greybus_frame - Structure to represent greybus HDLC frame payload
 *
 * @cport: cport id
 * @hdr: greybus operation header
 * @payload: greybus message payload
 *
 * The HDLC payload sent over UART for greybus address has cport preappended to
 * greybus message
 */
struct hdlc_greybus_frame {
  __le16 cport;
  struct gb_operation_msg_hdr hdr;
  u8 payload[];
} __packed;

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
  pr_info("GB_DEV: Sending %zu bytes in hex format", len);
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

static void hdlc_rx_greybus_frame(struct gb_device *gb_dev, u8 *buf, u16 len) {
  struct hdlc_greybus_frame *gb_frame = (struct hdlc_greybus_frame *)buf;
  u16 cport_id = le16_to_cpu(gb_frame->cport);
  u16 gb_msg_len = le16_to_cpu(gb_frame->hdr.size);

  pr_info("GB_DEV: Greybus Operation %u type %X cport %u status %u received",
          gb_frame->hdr.operation_id, gb_frame->hdr.type, cport_id,
          gb_frame->hdr.result);

  greybus_data_rcvd(gb_dev->gb_hd, cport_id, (u8 *)&gb_frame->hdr, gb_msg_len);
}

static void hdlc_rx_dbg_frame(const struct gb_device *gb_dev, const char *buf,
                              u16 len) {
  pr_info("GB_DEV: Log: %.*s", (int)len, buf);
}

/**
 * hdlc_write() - Consume HDLC Buffer.
 * @gb_dev: generic greybus driver
 *
 * Assumes that consumer lock has been acquired.
 */
static void hdlc_write(struct gb_device *gb_dev) {
  int written;
  /* Start consuming HDLC data */
  int head = smp_load_acquire(&gb_dev->tx_circ_buf.head);
  int tail = gb_dev->tx_circ_buf.tail;
  int count = CIRC_CNT_TO_END(head, tail, TX_CIRC_BUF_SIZE);
  const unsigned char *buf = &gb_dev->tx_circ_buf.buf[tail];

  if (count > 0) {
    int ret = gb_dev_send_message(gb_dev, buf, count);
    if (ret > 0) {

      /* Finish consuming HDLC data */
      smp_store_release(&gb_dev->tx_circ_buf.tail,
                        (tail + ret) & (TX_CIRC_BUF_SIZE - 1));
    }
  }
}

/**
 * hdlc_append() - Queue HDLC data for sending.
 * @gb_dev: generic greybus driver
 * @value: hdlc byte to transmit
 *
 * Assumes that producer lock as been acquired.
 */
static void hdlc_append(struct gb_device *gb_dev, u8 value) {
  int tail, head = gb_dev->tx_circ_buf.head;

  while (true) {
    tail = READ_ONCE(gb_dev->tx_circ_buf.tail);

    if (CIRC_SPACE(head, tail, TX_CIRC_BUF_SIZE) >= 1) {
      gb_dev->tx_circ_buf.buf[head] = value;

      /* Finish producing HDLC byte */
      smp_store_release(&gb_dev->tx_circ_buf.head,
                        (head + 1) & (TX_CIRC_BUF_SIZE - 1));
      return;
    }
    pr_warn("GB_DEV: Tx circ buf full");
    usleep_range(3000, 5000);
  }
}

static void hdlc_append_escaped(struct gb_device *gb_dev, u8 value) {
  if (value == HDLC_FRAME || value == HDLC_ESC) {
    hdlc_append(gb_dev, HDLC_ESC);
    value ^= HDLC_XOR;
  }
  hdlc_append(gb_dev, value);
}

static void hdlc_append_tx_frame(struct gb_device *gb_dev) {
  gb_dev->tx_crc = 0xFFFF;
  hdlc_append(gb_dev, HDLC_FRAME);
}

static void hdlc_append_tx_u8(struct gb_device *gb_dev, u8 value) {
  gb_dev->tx_crc = crc_ccitt(gb_dev->tx_crc, &value, 1);
  hdlc_append_escaped(gb_dev, value);
}

static void hdlc_append_tx_buf(struct gb_device *gb_dev, const u8 *buf,
                               u16 len) {
  size_t i;

  for (i = 0; i < len; i++)
    hdlc_append_tx_u8(gb_dev, buf[i]);
}

static void hdlc_append_tx_crc(struct gb_device *gb_dev) {
  gb_dev->tx_crc ^= 0xffff;
  hdlc_append_escaped(gb_dev, gb_dev->tx_crc & 0xff);
  hdlc_append_escaped(gb_dev, (gb_dev->tx_crc >> 8) & 0xff);
}

static void hdlc_transmit(struct work_struct *work) {
  struct gb_device *gb_dev = container_of(work, struct gb_device, tx_work);

  spin_lock_bh(&gb_dev->tx_consumer_lock);
  hdlc_write(gb_dev);
  spin_unlock_bh(&gb_dev->tx_consumer_lock);
}

static void hdlc_tx_frames(struct gb_device *gb_dev, u8 address, u8 control,
                           const struct hdlc_payload payloads[], size_t count) {
  size_t i;

  spin_lock(&gb_dev->tx_producer_lock);

  hdlc_append_tx_frame(gb_dev);
  hdlc_append_tx_u8(gb_dev, address);
  hdlc_append_tx_u8(gb_dev, control);

  for (i = 0; i < count; ++i)
    hdlc_append_tx_buf(gb_dev, payloads[i].buf, payloads[i].len);

  hdlc_append_tx_crc(gb_dev);
  hdlc_append_tx_frame(gb_dev);

  spin_unlock(&gb_dev->tx_producer_lock);

  schedule_work(&gb_dev->tx_work);
}

static void hdlc_tx_s_frame_ack(struct gb_device *gb_dev) {
  hdlc_tx_frames(gb_dev, gb_dev->rx_buffer[0],
                 (gb_dev->rx_buffer[1] >> 1) & 0x7, NULL, 0);
}

static void hdlc_rx_frame(struct gb_device *gb_dev) {
  u16 crc, len;
  u8 ctrl, *buf;
  u8 address = gb_dev->rx_buffer[0];

  crc = crc_ccitt(0xffff, gb_dev->rx_buffer, gb_dev->rx_buffer_len);
  if (crc != 0xf0b8) {
    // dev_warn_ratelimited(&gb_dev->ndev->dev, "CRC failed from %02x: 0x%04x",
    //                      address, crc);
    return;
  }

  ctrl = gb_dev->rx_buffer[1];
  buf = &gb_dev->rx_buffer[2];
  len = gb_dev->rx_buffer_len - 4;

  /* I-Frame, send S-Frame ACK */
  if ((ctrl & 1) == 0)
    hdlc_tx_s_frame_ack(gb_dev);

  switch (address) {
  case ADDRESS_DBG:
    hdlc_rx_dbg_frame(gb_dev, buf, len);
    break;
  case ADDRESS_GREYBUS:
    hdlc_rx_greybus_frame(gb_dev, buf, len);
    break;
  default:
    // dev_warn_ratelimited(&gb_dev->ndev->dev, "unknown frame %u", address);
  }
}

static size_t hdlc_rx(struct gb_device *gb_dev, const u8 *data, size_t count) {
  size_t i;
  u8 c;

  for (i = 0; i < count; ++i) {
    c = data[i];

    switch (c) {
    case HDLC_FRAME:
      if (gb_dev->rx_buffer_len)
        hdlc_rx_frame(gb_dev);

      gb_dev->rx_buffer_len = 0;
      break;
    case HDLC_ESC:
      gb_dev->rx_in_esc = true;
      break;
    default:
      if (gb_dev->rx_in_esc) {
        c ^= 0x20;
        gb_dev->rx_in_esc = false;
      }

      if (gb_dev->rx_buffer_len < MAX_RX_HDLC) {
        gb_dev->rx_buffer[gb_dev->rx_buffer_len] = c;
        gb_dev->rx_buffer_len++;
      } else {
        pr_err("GB_DEV: RX Buffer Overflow");
        gb_dev->rx_buffer_len = 0;
      }
    }
  }

  return count;
}

static int hdlc_init(struct gb_device *gb_dev) {
  pr_info("GB_DEV: Initializing HDLC\n");

  INIT_WORK(&gb_dev->tx_work, hdlc_transmit);
  spin_lock_init(&gb_dev->tx_producer_lock);
  spin_lock_init(&gb_dev->tx_consumer_lock);
  gb_dev->tx_circ_buf.head = 0;
  gb_dev->tx_circ_buf.tail = 0;

  gb_dev->tx_circ_buf.buf = kmalloc(TX_CIRC_BUF_SIZE, GFP_KERNEL);
  if (!gb_dev->tx_circ_buf.buf)
    return -ENOMEM;

  gb_dev->rx_buffer_len = 0;
  gb_dev->rx_in_esc = false;

  return 0;
}

static void hdlc_deinit(struct gb_device *gb_dev) {
  flush_work(&gb_dev->tx_work);
  kfree(gb_dev->tx_circ_buf.buf);
}

/**
 * csum8: Calculate 8-bit checksum on data
 *
 * @data: bytes to calculate 8-bit checksum of
 * @size: number of bytes
 * @base: starting value for checksum
 */
static u8 csum8(const u8 *data, size_t size, u8 base) {
  size_t i;
  u8 sum = base;

  for (i = 0; i < size; ++i)
    sum += data[i];

  return sum;
}

/**
 * gb_message_send() - Send greybus message using HDLC over UART
 *
 * @hd: pointer to greybus host device
 * @cport: AP cport where message originates
 * @msg: greybus message to send
 * @mask: gfp mask
 *
 * Greybus HDLC frame has the following payload:
 * 1. le16 cport
 * 2. gb_operation_msg_hdr msg_header
 * 3. u8 *msg_payload
 */
static int gb_message_send(struct gb_host_device *hd, u16 cport,
                           struct gb_message *msg, gfp_t mask) {
  struct gb_device *gb_dev = dev_get_drvdata(&hd->dev);
  struct hdlc_payload payloads[3];
  __le16 cport_id = cpu_to_le16(cport);

  dev_dbg(&hd->dev,
          "Sending greybus message with Operation %u, Type: %X on Cport %u",
          msg->header->operation_id, msg->header->type, cport);

  pr_info(
      "GB_DEV: Sending greybus message with Operation %u, Type: %X on Cport %u",
      msg->header->operation_id, msg->header->type, cport);

  if (le16_to_cpu(msg->header->size) > RX_HDLC_PAYLOAD) {
    return -E2BIG;
  }

  payloads[0].buf = &cport_id;
  payloads[0].len = sizeof(cport_id);
  payloads[1].buf = msg->header;
  payloads[1].len = sizeof(*msg->header);
  payloads[2].buf = msg->payload;
  payloads[2].len = msg->payload_size;

  hdlc_tx_frames(gb_dev, ADDRESS_GREYBUS, 0x03, payloads, 3);
  greybus_message_sent(gb_dev->gb_hd, msg, 0);

  return 0;
}

static void gb_message_cancel(struct gb_message *msg) {}

static struct gb_hd_driver gb_hdlc_driver = {
    .message_send = gb_message_send, .message_cancel = gb_message_cancel};

static void gb_dev_start_svc(struct gb_device *dev) {
  const u8 command = CONTROL_SVC_START;
  const struct hdlc_payload payload = {.len = 1, .buf = (void *)&command};

  hdlc_tx_frames(dev, ADDRESS_CONTROL, 0x03, &payload, 1);
}
static void gb_dev_stop_svc(struct gb_device *dev) {
  const u8 command = CONTROL_SVC_STOP;
  const struct hdlc_payload payload = {.len = 1, .buf = (void *)&command};

  hdlc_tx_frames(dev, ADDRESS_CONTROL, 0x03, &payload, 1);
}

static void gb_greybus_deinit(struct gb_device *gb_dev) {
  if (gb_dev->gb_hd) {
    gb_hd_del(gb_dev->gb_hd);
    gb_hd_put(gb_dev->gb_hd);
  }
}

static int gb_greybus_init(struct gb_device *gb_dev) {
  int ret;

  pr_info("GB_DEV: Creating greybus host device\n");
  gb_dev->gb_hd = gb_hd_create(&gb_hdlc_driver, &gb_dev->pdev->dev,
                               TX_CIRC_BUF_SIZE, GB_MAX_CPORTS);
  if (IS_ERR(gb_dev->gb_hd)) {
    pr_err("GB_DEV: Failed to create greybus host device\n");
    return PTR_ERR(gb_dev->gb_hd);
  }

  pr_info("GB_DEV: Adding greybus host device\n");
  ret = gb_hd_add(gb_dev->gb_hd);
  if (ret) {
    pr_err("GB_DEV: Failed to add greybus host device\n");
    goto free_gb_hd;
  }
  dev_set_drvdata(&gb_dev->gb_hd->dev, gb_dev);

  return 0;
free_gb_hd:
  gb_greybus_deinit(gb_dev);
  return ret;
}

/* Driver probe function */
static int gb_dev_probe(struct platform_device *pdev) {
  struct gb_device *gb_dev;
  struct sockaddr_in addr;
  int ret;

  pr_info("GB_DEV: Allocating memory for gb_dev");
  gb_dev = devm_kzalloc(&pdev->dev, sizeof(*gb_dev), GFP_KERNEL);
  if (!gb_dev)
    ret = -ENOMEM;
  gb_dev->pdev = pdev;

  pr_info("GB_DEV: Creating socket");
  ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
                         &gb_dev->sock);
  if (ret)
    return ret;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(gb_dev_port);
  addr.sin_addr.s_addr = in_aton(gb_dev_ip);

  ret = kernel_connect(gb_dev->sock, (struct sockaddr *)&addr, sizeof(addr), 0);
  if (ret)
    goto free_sock;

  ret = hdlc_init(gb_dev);
  if (ret)
    goto free_hdlc;

  ret = gb_greybus_init(gb_dev);
  pr_info("GB_DEV: Greybus Initialized ret %d", ret);
  if (ret)
    goto free_greybus;

  pr_info("GB_DEV: Starting SVC");
  gb_dev_start_svc(gb_dev);

  return 0;

free_greybus:
  gb_greybus_deinit(gb_dev);
free_hdlc:
  hdlc_deinit(gb_dev);
free_sock:
  sock_release(gb_dev->sock);
  return ret;
}

static int gb_dev_remove(struct platform_device *pdev) {
  struct gb_device *gb_dev = platform_get_drvdata(pdev);

  if (!gb_dev)
    return -EINVAL;

  gb_greybus_deinit(gb_dev);
  gb_dev_stop_svc(gb_dev);
  hdlc_deinit(gb_dev);
  sock_release(gb_dev->sock);

  return 0;
}

static struct platform_driver gb_platform_driver = {
    .probe = gb_dev_probe,
    .remove = gb_dev_remove,
    .driver =
        {
            .name = "gb-device",
            .owner = THIS_MODULE,
        },
};

static struct platform_device *gb_pdev;

static int __init gb_dev_init(void) {
  int ret;
  pr_info("GB_DEV: Initializing Generic Greybus Device\n");

  ret = platform_driver_register(&gb_platform_driver);
  if (ret) {
    pr_err("GB_DEV: Failed to register platform driver\n");
    return ret;
  }

  gb_pdev = platform_device_alloc("gb-device", -1);
  if (!gb_pdev) {
    pr_err("GB_DEV: Failed to allocate platform device\n");
    return -ENOMEM;
  }
  ret = platform_device_add(gb_pdev);
  if (ret) {
    pr_err("GB_DEV: Failed to add platform device\n");
    platform_device_put(gb_pdev);
    return ret;
  }
  return 0;
}

static void __exit gb_dev_exit(void) {
  if (gb_pdev) {
    platform_device_unregister(gb_pdev);
  }
  platform_driver_unregister(&gb_platform_driver);
  pr_info("GB_DEV: Exiting Generic Greybus Device\n");
}

module_init(gb_dev_init);
module_exit(gb_dev_exit);

MODULE_DESCRIPTION("Generic greybus driver over Wi-Fi");
MODULE_AUTHOR("Harshil Bhatt <harshilbhatt2001@gmail.com>");
MODULE_LICENSE("GPL");
