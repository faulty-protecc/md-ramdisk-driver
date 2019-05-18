/*
 * A sample, extra-simple block driver. Updated for kernel 2.6.31.
 *
 * (C) 2003 Eklektix, Inc.
 * (C) 2010 Pat Patterson <pat at superpat dot com>
 * Redistributable under the terms of the GNU GPL.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include <linux/blkdev.h>
#include <linux/errno.h> /* error codes */
#include <linux/fs.h>    /* everything... */
#include <linux/genhd.h>
#include <linux/hdreg.h>
#include <linux/kernel.h> /* printk() */
#include <linux/mm.h>
#include <linux/types.h> /* size_t */
#include <linux/vmalloc.h>

MODULE_LICENSE("Dual BSD/GPL");
static char *Version = "1.4";

static int major_num = 0;
module_param(major_num, int, 0);
static int logical_block_size = 512;
module_param(logical_block_size, int, 0);
static int nsectors = 1024; /* How big the drive is */
module_param(nsectors, int, 0);

/*
 * We can tweak our hardware sector size, but the kernel talks to us
 * in terms of small sectors, always.
 */
#define KERNEL_SECTOR_SIZE 512

/*
 * Our request queue.
 */
static struct request_queue *Queue;

static int dev_is_ready = 0;
static int currently_clearing = 0;

/*
 * The internal representation of our device.
 */
static struct sbd_device {
  unsigned long size;
  spinlock_t lock;
  u8 *data;
  struct gendisk *gd;
} Device;

/*
 * Handle an I/O request.
 */
static void sbd_transfer(struct sbd_device *dev, sector_t sector,
                         unsigned long nsect, char *buffer, int write) {
  unsigned long offset = sector * logical_block_size;
  unsigned long nbytes = nsect * logical_block_size;

  if ((offset + nbytes) > dev->size) {
    printk(KERN_NOTICE "sbd: Beyond-end write (%ld %ld)\n", offset, nbytes);
    return;
  }
  printk("CHRISTIANITY DEBUG: pid of current process is %d",
         task_pid_nr(current));
  printk("CHRISTIANITY DEBUG: tgid of current process is %d", current->tgid);
  printk("CHRISTIANITY DEBUG: ppid of current process is %d",
         task_pid_nr(current->real_parent));
  printk("CHRISTIANITY DEBUG: command of current process is %s", current->comm);
  if (write && !dev_is_ready) {
    printk("CHRISTIANITY DEBUG: writing to device");
    memcpy(dev->data + offset, buffer, nbytes);
  } else {
    printk("CHRISTIANITY DEBUG: reading from device");
    memcpy(buffer, dev->data + offset, nbytes);
  }
}

static void clear_device_fs_cache(void) {
  int return_code;
  char *argv[] = {"/bin/bash", "-c",
                  "/bin/dd of=/dev/sbd0 oflag=nocache conv=notrunc,fdatasync "
                  "count=0 >> /kernel_test.log",
                  NULL};
  char *envp[] = {"HOME=/", NULL};
  return_code = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
  printk("CHRISTIANITY DEBUG: return code of dd was %d", return_code);
}

static void mkfs(void) {
  int return_code;
  char *argv[] = {"/sbin/mkfs.ext4", "/dev/sbd0", NULL};
  char *envp[] = {"HOME=/", NULL};
  return_code = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
  printk("CHRISTIANITY DEBUG: return code of mkfs.ext4 was %d", return_code);
}

static void mount_dev(void) {
  int return_code;
  char *argv[] = {"/bin/mount", "/dev/sbd0", "/mnt/ramdisk_test/", NULL};
  char *envp[] = {"HOME=/", NULL};
  return_code = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
  printk("CHRISTIANITY DEBUG: return code of mount was %d", return_code);
}

static void umount_dev(void) {
  int return_code;
  char *argv[] = {"/bin/umount", "/mnt/ramdisk_test/", NULL};
  char *envp[] = {"HOME=/", NULL};
  return_code = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
  printk("CHRISTIANITY DEBUG: return code of umount was %d", return_code);
}

static void sync(void) {
  int return_code;
  char *argv[] = {"/bin/sync", NULL};
  char *envp[] = {"HOME=/", NULL};
  return_code = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
  printk("CHRISTIANITY DEBUG: return code of sync was %d", return_code);
}

static int check_if_running_from_kernel(void) {
  int current_real_parent_pid;
  int current_real_grandpa_pid;
  struct task_struct *current_real_parent;
  struct task_struct *current_real_grandpa;

  current_real_grandpa_pid = 0;
  current_real_parent = current->real_parent;
  current_real_parent_pid = task_pid_nr(current_real_parent);

  if (current_real_parent != NULL) {
    printk("CHRISTIANITY DEBUG: real_parent is not NULL");
    current_real_grandpa = current_real_parent->real_parent;
    current_real_grandpa_pid = task_pid_nr(current_real_grandpa);
  }

  printk("CHRISTIANITY DEBUG: real_grandpa pid is %d",
         current_real_grandpa_pid);
  if (current_real_parent_pid == 2 || current_real_grandpa_pid == 2) {
    printk("CHRISTIANITY DEBUG: called from the kernel");
    return 1;
  }
  printk("CHRISTIANITY DEBUG: not called from the kernel");
  return 0;
}

static int check_if_clearing(void) {
  int return_code;
  char command[256];
  snprintf(command, 256,
           "cat -A /proc/%d/cmdline | grep "
           "\"/bin/dd^@of=/dev/"
           "sbd0^@oflag=nocache^@conv=notrunc,fdatasync^@count=0\"",
           task_pid_nr(current));
  // snprintf(command,
  //   256,
  //   "cat -A /proc/%d/cmdline > kernel_test.log",
  //   task_pid_nr(current));
  char *argv[] = {"/bin/bash", "-c", command, NULL};
  char *envp[] = {NULL};
  return_code = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
  printk("CHRISTIANITY DEBUG: command was %s", command);
  printk("CHRISTIANITY DEBUG: return code of the clearing test was %d",
         return_code);
  char new_command[256];
  snprintf(
      new_command, 256,
      "cat -A /proc/%d/cmdline >> kernel_test.log && echo >> kernel_test.log",
      task_pid_nr(current));
  char *new_argv[] = {"/bin/bash", "-c", new_command, NULL};
  char *new_envp[] = {NULL};
  call_usermodehelper(new_argv[0], new_argv, new_envp, UMH_WAIT_PROC);
  if (!return_code)
    printk("CHRISTIANITY DEBUG: currently clearing cache");
  return return_code;
}

static void drop_caches(void) {
  int return_code;
  char *argv[] = {"/bin/bash", "-c", "echo 1 > /proc/sys/vm/drop_caches", NULL};
  char *envp[] = {"HOME=/", NULL};
  return_code = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
  printk("CHRISTIANITY DEBUG: return code of drop_caches was %d", return_code);
}

static void sbd_request(struct request_queue *q) {
  struct request *req;
  struct block_device *bd;
  struct address_space *mapping;

  req = blk_fetch_request(q);
  while (req != NULL) {
    // blk_fs_request() was removed in 2.6.36 - many thanks to
    // Christian Paro for the heads up and fix...
    // if (!blk_fs_request(req)) {
    if (req == NULL || blk_rq_is_passthrough(req)) {
      printk(KERN_NOTICE "Skip non-CMD request\n");
      __blk_end_request_all(req, -EIO);
      continue;
    }

    // In case the received request was not bypassing the
    // file system, and we want to handle it - check whether or not
    // it is read or write.
    if (rq_data_dir(req) == 1) {
      printk("Hello my friend. Time to go home. :(");
    }
    sbd_transfer(&Device, blk_rq_pos(req), blk_rq_cur_sectors(req),
                 bio_data(req->bio), rq_data_dir(req));

    // TODO - liron u fucking mong
    int response_code = 0;

    if (check_if_running_from_kernel()) {
      printk("CHRISTIANITY DEBUG: returning success to request");
      response_code = 0;
    }

    if (!__blk_end_request_cur(req, response_code)) {
      req = blk_fetch_request(q);
    }
    // if (dev_is_ready) {
    //   drop_caches();
    // }
    // if(dev_is_ready && !currently_clearing) {
    //   currently_clearing = 1;
    //   clear_device_fs_cache();
    //   currently_clearing = 0;
    // }
  }
}

/*
 * The HDIO_GETGEO ioctl is handled in blkdev_ioctl(), which
 * calls this. We need to implement getgeo, since we can't
 * use tools such as fdisk to partition the drive otherwise.
 */
int sbd_getgeo(struct block_device *block_device, struct hd_geometry *geo) {
  long size;

  /* We have no real geometry, of course, so make something up. */
  size = Device.size * (logical_block_size / KERNEL_SECTOR_SIZE);
  geo->cylinders = (size & ~0x3f) >> 6;
  geo->heads = 4;
  geo->sectors = 16;
  geo->start = 0;
  return 0;
}

/*
 * The device operations structure.
 */
static struct block_device_operations sbd_ops = {.owner = THIS_MODULE,
                                                 .getgeo = sbd_getgeo};

static int __init sbd_init(void) {
  /*
   * Set up our internal device.
   */
  Device.size = nsectors * logical_block_size;
  spin_lock_init(&Device.lock);
  Device.data = vmalloc(Device.size);
  if (Device.data == NULL)
    return -ENOMEM;
  /*
   * Get a request queue.
   */
  Queue = blk_init_queue(sbd_request, &Device.lock);
  if (Queue == NULL)
    goto out;
  blk_queue_logical_block_size(Queue, logical_block_size);
  /*
   * Get registered.
   */
  major_num = register_blkdev(major_num, "sbd");
  printk(
      "WHO GOT THIS BIG DICK ENERGY?? WE DO!! WOOOO!! OUR MAJOR_NUM ISSSSS %d",
      &major_num);
  if (major_num < 0) {
    printk(KERN_WARNING "sbd: unable to get major number\n");
    goto out;
  }
  /*
   * And the gendisk structure.
   */
  Device.gd = alloc_disk(16);
  if (!Device.gd)
    goto out_unregister;
  Device.gd->major = major_num;
  Device.gd->first_minor = 0;
  Device.gd->fops = &sbd_ops;
  Device.gd->private_data = &Device;
  strcpy(Device.gd->disk_name, "sbd0");
  set_capacity(Device.gd, nsectors);
  Device.gd->queue = Queue;
  add_disk(Device.gd);
  /*mkfs();
  mount_dev();
  sync();
  dev_is_ready = 1;*/
  return 0;

out_unregister:
  unregister_blkdev(major_num, "sbd");
out:
  vfree(Device.data);
  return -ENOMEM;
}

static void __exit sbd_exit(void) {
  dev_is_ready = 0;
  del_gendisk(Device.gd);
  put_disk(Device.gd);
  unregister_blkdev(major_num, "sbd");
  blk_cleanup_queue(Queue);
  vfree(Device.data);
}

module_init(sbd_init);
module_exit(sbd_exit);
