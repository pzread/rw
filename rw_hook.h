#define HOOK_INFO_HASHSIZE 97

struct hook_bio_info{
    atomic_t remain;
    struct bio *ori_bio;
    struct rw_hook_info *hook_info;
};

static struct kmem_cache *rw_hook_info_cachep;
static struct kmem_cache *hook_bio_info_cachep;
static DEFINE_SPINLOCK(hook_info_hash_lock);
static struct hlist_head hook_info_hash[HOOK_INFO_HASHSIZE];

static int hook_watcher(void *data);
static struct rw_hook_info* hook_info_lookup(struct gendisk *gd);
static void hook_make(struct request_queue *q, struct bio *bio);
static void hook_end_bio(struct hook_bio_info *bio_info,unsigned int size);
static void hook_loaded(void *loaded_private);

atomic_t hook_count;

void rw_hook_init(void);
int rw_hook_install(struct gendisk *gd);
int rw_hook_writeback_all(bool reboot);

extern bool rw_reboot_flag;
extern struct completion rw_reboot_wait;

extern struct rw_cache_info* rw_cache_create(struct rw_hook_info *hook_info);
extern struct rw_cache_cluster* rw_cache_get_cluster(struct rw_cache_info *ca_info,unsigned long addr);
extern u8* rw_cache_alloc_sector(struct rw_cache_info *ca_info);
extern int rw_cache_wait_sector(struct rw_cache_cluster *ca_cluster,unsigned int idx,u8 *buffer,rw_loaded_fn loaded_fn,void *loaded_private);
extern int rw_cache_load(struct rw_cache_info *ca_info,struct block_device *bdev,sector_t start,unsigned int size);
extern int rw_cache_scan(struct rw_cache_info *ca_info,unsigned long free_limit,unsigned long write_limit,unsigned int flags);
