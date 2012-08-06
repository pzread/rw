#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/types.h>
#include<linux/kdev_t.h>
#include<linux/device.h>
#include<linux/cdev.h>
#include<linux/blkdev.h>
#include<linux/reboot.h>
#include<linux/fs.h>

#include"rw.h"
#include"rw_mod.h"

#define IOCTL_APP_GET _IOR('x',0x0,int)

static int __init rw_init(){
    alloc_chrdev_region(&rw_dev,0,1,"rw"); 
    rw_class = class_create(THIS_MODULE,"chardrv");
    device_create(rw_class,NULL,rw_dev,NULL,"rw");
    cdev_init(&rw_cdev,&rw_fops);
    cdev_add(&rw_cdev,rw_dev,1);

    pr_alert("RW:Version 2\n");
    rw_test();

    pr_alert("RW:Init\n");
    return 0;
}
static void __exit rw_exit(){
    cdev_del(&rw_cdev);
    device_destroy(rw_class,rw_dev);
    class_destroy(rw_class);
    unregister_chrdev_region(rw_dev,1);

    pr_alert("RW:Exit\n");
}
module_init(rw_init);
module_exit(rw_exit);
MODULE_LICENSE("GPL");

static int rw_open(struct inode *i,struct file *f){
    return 0;
}
static int rw_release(struct inode *i,struct file *f){
    return 0;
}
static long rw_ioctl(struct file *f,unsigned int cmd,unsigned long arg){
    switch(cmd){
	case IOCTL_APP_GET:
	    break;
    }

    return 0;
}

static int rw_reboot(struct notifier_block *nb,unsigned long action,void *dev){
    rw_reboot_flag = true;
    wait_for_completion_interruptible(&rw_reboot_wait);

    return NOTIFY_OK;
}

static int rw_test(){
    struct gendisk *gd;
    int no;

    rw_hook_init();
    rw_cache_init();

    gd = get_gendisk(MKDEV(8,0),&no);
    pr_alert("%016lx %d\n",(unsigned long)gd,no);

    //pr_alert("%016lx\n",(unsigned long)bdget(MKDEV(254,0)));
    //pr_alert("%016lx\n",(unsigned long)bdget_disk(gd,0));

    rw_hook_install(gd); 

    register_reboot_notifier(&reboot_nb);

    return 0;
}