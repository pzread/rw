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

static int __init rw_init(){
    alloc_chrdev_region(&rw_dev,0,1,"rw"); 
    rw_class = class_create(THIS_MODULE,"chardrv");
    device_create(rw_class,NULL,rw_dev,NULL,"rw");
    cdev_init(&rw_cdev,&rw_fops);
    cdev_add(&rw_cdev,rw_dev,1);

    pr_alert("RW:4.3 Mint Choco\n");
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
module_param(rw_test_major,int,S_IRUGO);
module_param(rw_test_minor,int,S_IRUGO);
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

    gd = get_gendisk(MKDEV(rw_test_major,rw_test_minor),&no);
    pr_alert("RW:%016lx %d\n",(unsigned long)gd,no);

    if(gd != NULL){
	rw_hook_install(gd); 
	register_reboot_notifier(&reboot_nb);
    }

    return 0;
}
