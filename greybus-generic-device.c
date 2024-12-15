#include "greybus-generic-device.h"
#include "greybus-hdlc.h"
#include <linux/circ_buf.h>
#include <linux/crc-ccitt.h>
#include <linux/crc32.h>
#include <linux/greybus.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_port.h>
#include <linux/types.h>
#include <linux/workqueue.h>

// module_param(gb_dev_name, charp, 0644);
// MODULE_PARM_DESC(gb_dev_name, "Name of the greybus device");
module_param(gb_dev_serial_port, charp, 0644);
MODULE_PARM_DESC(gb_dev_serial_port, "Serial port of the greybus device");

static struct tty_struct *get_tty_device(const char *device_path) {
  struct file *file;
  struct tty_struct *tty = NULL;

  // Open the device file
  file = filp_open(device_path, O_RDWR | O_NOCTTY, 0);
  if (IS_ERR(file)) {
    printk(KERN_ERR "Could not open %s, error: %ld\n", device_path,
           PTR_ERR(file));
    return NULL;
  }

  // Get the device number
  dev_t device = file->f_inode->i_rdev;
  filp_close(file, NULL);

  // Open the TTY for shared kernel use
  tty = tty_kopen_shared(device);
  if (!tty) {
    printk(KERN_ERR "Could not open tty device number %d:%d\n", MAJOR(device),
           MINOR(device));
    return NULL;
  }

  return tty;
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
  struct tty_struct *tty;
  char device_path[64];
  int ret;

  pr_info("GB_DEV: Probing device\n");

  gb_dev = devm_kzalloc(&pdev->dev, sizeof(*gb_dev), GFP_KERNEL);
  if (!gb_dev) {
    pr_info("GB_DEV: Failed to allocate memory for gb_dev\n");
    return -ENOMEM;
  }

  snprintf(device_path, sizeof(device_path), "/dev/%s", gb_dev_serial_port);
  tty = get_tty_device(device_path);
  if (IS_ERR_OR_NULL(tty)) {
    pr_err("GB_DEV: Failed to find TTY device %s: %ld\n", gb_dev_serial_port,
           PTR_ERR(tty));
    // dev_err(&pdev->dev, "Failed to find TTY device %s: %ld\n",
    //         gb_dev_serial_port, PTR_ERR(tty));
    return PTR_ERR(tty);
  } else {
    pr_info("GB_DEV: Found TTY device %s\n", gb_dev_serial_port);
  }

  gb_dev->tty = tty;
  gb_dev->pdev = pdev;
  platform_set_drvdata(pdev, gb_dev);

  ret = hdlc_init(gb_dev);
  if (ret)
    goto free_hdlc;

  ret = gb_greybus_init(gb_dev);
  if (ret)
    goto free_greybus;

  pr_info("GB_DEV: Starting SVC");
  gb_dev_start_svc(gb_dev);

  return 0;

free_greybus:
  gb_greybus_deinit(gb_dev);
free_hdlc:
  hdlc_deinit(gb_dev);
put_tty:
  tty_kclose(tty);
  return ret;
}

static int gb_dev_remove(struct platform_device *pdev) {
  struct gb_device *gb_dev = platform_get_drvdata(pdev);

  if (!gb_dev)
    return -EINVAL;

  gb_greybus_deinit(gb_dev);
  gb_dev_stop_svc(gb_dev);
  hdlc_deinit(gb_dev);

  if (gb_dev->tty)
    tty_kclose(gb_dev->tty);

  return 0;
}

static struct platform_driver gb_platform_driver = {
    .probe = gb_dev_probe,
    .remove = (void *)gb_dev_remove,
    .driver =
        {
            .name = "gb-dev",
            .owner = THIS_MODULE,
        },
};

static struct platform_device *gb_platform_device;

static int __init gb_dev_init(void) {
  int ret;
  pr_info("GB_DEV: Registering driver\n");

  ret = platform_driver_register(&gb_platform_driver);
  if (ret) {
    return ret;
  }

  gb_platform_device = platform_device_alloc("gb-dev", -1);
  if (!gb_platform_device) {
    ret = -ENOMEM;
    goto unregister_driver;
  }

  ret = platform_device_add(gb_platform_device);
  if (ret)
    goto put_device;

  pr_info("GB_DEV: Created and added platform device\n");

  return 0;

put_device:
  platform_device_put(gb_platform_device);
unregister_driver:
  platform_driver_unregister(&gb_platform_driver);
  return ret;
}

static void __exit gb_dev_exit(void) {
  pr_info("GB_DEV: Exiting greybus driver\n");
  platform_device_unregister(gb_platform_device);
  platform_driver_unregister(&gb_platform_driver);
}

module_init(gb_dev_init);
module_exit(gb_dev_exit);

MODULE_DESCRIPTION("Generic greybus driver");
MODULE_AUTHOR("Harshil Bhatt <harshilbhatt2001@gmail.com>");
MODULE_LICENSE("GPL");
