struct cache_req_info{
    sector_t start;
    unsigned int size;
    struct rw_cache_info *ca_info;
};
struct cache_freeback_info{
    struct cache_freeback_info *next;
    u8 *sector;
};
struct cache_writeback_info{
    struct semaphore *bucket;
    atomic_t *remain;
    struct completion *wait;
};

static struct kmem_cache *rw_cache_info_cachep;
static struct kmem_cache *rw_cache_cluster_cachep;
static struct kmem_cache *rw_wait_sector_cachep;
static struct kmem_cache *cache_sector_cachep;
static struct kmem_cache *cache_req_info_cachep;
static struct kmem_cache *cache_freeback_info_cachep;
static struct kmem_cache *cache_writeback_info_cachep;

static void cache_load_endio(struct bio *bio,int error);
static void cache_freeback(struct rw_cache_info *ca_info,struct rw_cache_cluster *ca_cluster,unsigned long *free_limit,struct cache_freeback_info **fb_list);
static void cache_writeback(struct rw_cache_info *ca_info,struct rw_cache_cluster *ca_cluster,unsigned long *write_limit,struct semaphore *bucket,atomic_t *remain,struct completion *wait);
static void cache_writeback_endio(struct bio *bio,int error);

void rw_cache_init(void);
struct rw_cache_info* rw_cache_create(struct rw_hook_info *hook_info);

struct rw_cache_cluster* rw_cache_get_cluster(struct rw_cache_info *ca_info,unsigned long addr);
u8* rw_cache_alloc_sector(struct rw_cache_info *ca_info);
int rw_cache_wait_sector(struct rw_cache_cluster *ca_cluster,unsigned int idx,u8 *buffer,rw_loaded_fn loaded_fn,void *loaded_private);

int rw_cache_load(struct rw_cache_info *ca_info,struct block_device *bdev,sector_t start,unsigned int size);
int rw_cache_scan(struct rw_cache_info *ca_info,unsigned long free_limit,unsigned long write_limit,unsigned int flags);
