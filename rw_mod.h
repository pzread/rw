static int __init rw_init(void);
static void __exit rw_exit(void);
static int rw_open(struct inode *i,struct file *f);
static int rw_release(struct inode *i,struct file *f);
static long rw_ioctl(struct file *f,unsigned int cmd,unsigned long arg);

static dev_t rw_dev;
static struct cdev rw_cdev;
static struct class *rw_class;
static struct file_operations rw_fops = {
    .owner = THIS_MODULE,
    .open = rw_open,
    .release = rw_release,
    .unlocked_ioctl = rw_ioctl
};

static int rw_reboot(struct notifier_block *nb,unsigned long action,void *dev);
static int rw_test(void);

static struct notifier_block reboot_nb = {
    .notifier_call = rw_reboot,
    .priority = 0
};

bool rw_reboot_flag;
DECLARE_COMPLETION(rw_reboot_wait);

extern void rw_hook_init(void);
extern int rw_hook_install(struct gendisk *gd);
extern void rw_cache_init(void);
extern int rw_hook_writeback_all(bool reboot);

extern void hook_info_lookup(struct gendisk *gd);

