#ifndef _GREYBUS_GENERIC_DEVICE_H
#define _GREYBUS_GENERIC_DEVICE_H

#include "greybus-hdlc.h"
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
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/serdev.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_port.h>
#include <linux/workqueue.h>

#define DEFAULT_GREYBUS_DEVICE_NAME "gb-device"
#define DEFAULT_GREYBUS_DEVICE_SERIAL_PORT "ttyUSB0"

#define CONTROL_SVC_START 0x01
#define CONTROL_SVC_STOP 0x02

/* The maximum number of CPorts supported by Greybus Host Device */
#define GB_MAX_CPORTS 32

#if 0
/**
 * struct gb_device - Greybus device structure
 *
 * @gb_hd: greybus host device
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
  struct tty_struct *tty;
  struct device *dev;

  struct gb_host_device *gb_hd;

  struct work_struct tx_work;
  spinlock_t tx_producer_lock;
  spinlock_t tx_consumer_lock;
  struct circ_buf tx_circ_buf;
  u16 tx_crc;

  u16 rx_buffer_len;
  bool rx_in_esc;
  u8 rx_buffer[MAX_RX_HDLC];

  bool initialized;
  struct mutex ops_mutex;
  char dev_path[64];
};
#endif

/* Module parameters */
// static char *gb_dev_ip = DEFAULT_GREYBUS_DEVICE_IP_ADDRESS;
// static int gb_dev_port = DEFAULT_GREYBUS_DEVICE_PORT;
static char *gb_dev_name = DEFAULT_GREYBUS_DEVICE_NAME;
static char *gb_dev_serial_port = DEFAULT_GREYBUS_DEVICE_SERIAL_PORT;

#endif // _GREYBUS_GENERIC_DEVICE_H
