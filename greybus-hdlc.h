#ifndef _GREYBUS_HDLC_H
#define _GREYBUS_HDLC_H

#include <linux/circ_buf.h>
#include <linux/greybus.h>
#include <linux/types.h>
#include <linux/workqueue.h>

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
  struct platform_device *pdev;

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

void hdlc_tx_frames(struct gb_device *gb_dev, u8 address, u8 control,
                    const struct hdlc_payload payloads[], size_t count);
size_t hdlc_rx(struct gb_device *gb_dev, const u8 *data, size_t count);
int hdlc_init(struct gb_device *gb_dev);
void hdlc_deinit(struct gb_device *gb_dev);

#endif // _GREYBUS_HDLC_H
