#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/fs.h>

#define TTY_DEVICE_PATH "/dev/ttyUSB0"
#define WRITE_INTERVAL_MS 1000

static struct tty_struct *esp32_tty;
static struct task_struct *write_thread;
static bool thread_should_stop;

// Function to find and get the TTY device
static struct tty_struct *get_tty_device(const char *device_path)
{
    struct file *file;
    struct tty_struct *tty = NULL;
    
    // Open the device file
    file = filp_open(device_path, O_RDWR | O_NOCTTY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Could not open %s, error: %ld\n", 
               device_path, PTR_ERR(file));
        return NULL;
    }
    
    // Get the device number
    dev_t device = file->f_inode->i_rdev;
    filp_close(file, NULL);
    
    // Open the TTY for shared kernel use
    tty = tty_kopen_shared(device);
    if (!tty) {
        printk(KERN_ERR "Could not open tty device number %d:%d\n",
               MAJOR(device), MINOR(device));
        return NULL;
    }
    
    return tty;
}

// Example write function
static void write_to_tty(struct tty_struct *tty, const char *str)
{
    if (tty && tty->ops && tty->ops->write) {
        int len = strlen(str);
        tty->ops->write(tty, str, len);
    }
}

// Thread function for periodic writes
static int write_thread_fn(void *data)
{
    const char *test_msg = "Hello from kernel\n";
    
    while (!kthread_should_stop() && !thread_should_stop) {
        write_to_tty(esp32_tty, test_msg);
        msleep(WRITE_INTERVAL_MS);
    }
    
    return 0;
}

static int __init esp32_init(void)
{
    // Find and open the TTY device
    esp32_tty = get_tty_device(TTY_DEVICE_PATH);
    if (!esp32_tty) {
        printk(KERN_ERR "Failed to open %s\n", TTY_DEVICE_PATH);
        return -ENODEV;
    }

    // Create and start the write thread
    thread_should_stop = false;
    write_thread = kthread_run(write_thread_fn, NULL, "esp32_write_thread");
    if (IS_ERR(write_thread)) {
        printk(KERN_ERR "Failed to create kernel thread\n");
        tty_kclose(esp32_tty);
        return PTR_ERR(write_thread);
    }

    printk(KERN_INFO "ESP32 kernel module loaded\n");
    return 0;
}

static void __exit esp32_exit(void)
{
    // Stop the write thread
    if (write_thread) {
        thread_should_stop = true;
        kthread_stop(write_thread);
    }

    // Close the TTY device
    if (esp32_tty) {
        tty_kclose(esp32_tty);
    }

    printk(KERN_INFO "ESP32 kernel module unloaded\n");
}

module_init(esp32_init);
module_exit(esp32_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module for ESP32 TTY communication");
MODULE_VERSION("1.0");
