#include "greybus-generic-device.h"
#include <linux/circ_buf.h>
#include <linux/crc-ccitt.h>
#include <linux/crc32.h>
#include <linux/greybus.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_port.h>
#include <linux/workqueue.h>

static void hdlc_rx_greybus_frame(struct gb_device *gb_dev, u8 *buf, u16 len) {
  struct hdlc_greybus_frame *gb_frame = (struct hdlc_greybus_frame *)buf;
  u16 cport_id = le16_to_cpu(gb_frame->cport);
  u16 gb_msg_len = le16_to_cpu(gb_frame->hdr.size);

  pr_info("GB_DEV: Greybus Operation %u type %X cport %u status %u received",
          gb_frame->hdr.operation_id, gb_frame->hdr.type, cport_id,
          gb_frame->hdr.result);

  // dev_dbg(&gb_dev->port->dev,
  //         "Greybus Operation %u type %X cport %u status %u received",
  //         gb_frame->hdr.operation_id, gb_frame->hdr.type, cport_id,
  //         gb_frame->hdr.result);

  greybus_data_rcvd(gb_dev->gb_hd, cport_id, (u8 *)&gb_frame->hdr, gb_msg_len);
}

static void hdlc_rx_dbg_frame(const struct gb_device *gb_dev, const char *buf,
                              u16 len) {
  pr_info("GB_DEV: Log: %.*s", (int)len, buf);
  // dev_dbg(&gb_dev->port->dev, "Log: %.*s", (int)len, buf);
}

static int gb_tty_write(struct gb_device *gb_dev, const unsigned char *buf,
                        size_t count) {
  int ret;
  struct tty_struct *tty = gb_dev->tty;
  if (!tty || !tty->ops->write)
    return -ENODEV;

  ret = tty->ops->write(tty, buf, count);
  if (ret < 0)
    pr_err("GB_DEV: Failed to write to tty: %d\n", ret);
  else {
    pr_info("GB_DEV: Sent %zu bytes in hex format: ", count);
    print_hex_dump(KERN_INFO, "GB_DEV: ", DUMP_PREFIX_OFFSET, 16, 1, buf, count,
                   false);
  }

  return ret;
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
    written = gb_tty_write(gb_dev, buf, count);

    /* Finish consuming HDLC data */
    smp_store_release(&gb_dev->tx_circ_buf.tail,
                      (tail + written) & (TX_CIRC_BUF_SIZE - 1));
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
    // dev_warn(&gb_dev->port->dev, "Tx circ buf full");
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

void hdlc_tx_frames(struct gb_device *gb_dev, u8 address, u8 control,
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
    // dev_warn_ratelimited(&gb_dev->port->dev, "CRC failed from %02x: 0x%04x",
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
    // dev_warn_ratelimited(&gb_dev->port->dev, "unknown frame %u", address);
  }
}

size_t hdlc_rx(struct gb_device *gb_dev, const u8 *data, size_t count) {
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
        // dev_err(&gb_dev->port->dev, "RX Buffer Overflow");
        gb_dev->rx_buffer_len = 0;
      }
    }
  }

  return count;
}

int hdlc_init(struct gb_device *gb_dev) {
  pr_info("GB_DEV: Initializing HDLC\n");

  INIT_WORK(&gb_dev->tx_work, hdlc_transmit);
  spin_lock_init(&gb_dev->tx_producer_lock);
  spin_lock_init(&gb_dev->tx_consumer_lock);
  gb_dev->tx_circ_buf.head = 0;
  gb_dev->tx_circ_buf.tail = 0;

  pr_info("GB_DEV: Allocating HDLC buffer\n");
  gb_dev->tx_circ_buf.buf = kzalloc(TX_CIRC_BUF_SIZE, GFP_KERNEL);
  if (!gb_dev->tx_circ_buf.buf) {
    pr_err("GB_DEV: Failed to allocate memory for HDLC buffer\n");
    return -ENOMEM;
  }

  gb_dev->rx_buffer_len = 0;
  gb_dev->rx_in_esc = false;

  return 0;
}

void hdlc_deinit(struct gb_device *gb_dev) {
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
static __maybe_unused u8 csum8(const u8 *data, size_t size, u8 base) {
  size_t i;
  u8 sum = base;

  for (i = 0; i < size; ++i)
    sum += data[i];

  return sum;
}
