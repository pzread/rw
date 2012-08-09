struct cache_req_info{
    sector_t start;
    unsigned int size;
    struct rw_cache_info *ca_info;
};
struct cache_writeback_info{
    struct semaphore *bucket;
    atomic_t *remain;
    struct completion *wait;
};

static struct kmem_cache *rw_cache_info_cachep;
static struct kmem_cache *rw_cache_cluster_cachep;
static struct kmem_cache *rw_wait_sector_cachep;
static struct kmem_cache *cache_req_info_cachep;
static struct kmem_cache *cache_writeback_info_cachep;
static DEFINE_PER_CPU(u8*,cache_sector_pool);
static DEFINE_PER_CPU(unsigned int,cache_sector_pool_count);

static void cache_endio(struct bio *bio,int error);
static void cache_writeback_endio(struct bio *bio,int error);

void rw_cache_init(void);
struct rw_cache_info* rw_cache_create(struct rw_hook_info *hook_info);

struct rw_cache_cluster* rw_cache_get_cluster(struct rw_cache_info *ca_info,unsigned long addr);
u8* rw_cache_alloc_sector(void);
int rw_cache_wait_sector(struct rw_cache_cluster *ca_cluster,unsigned int idx,u8 *buffer,rw_loaded_fn loaded_fn,void *loaded_private);

int rw_cache_load(struct rw_cache_info *ca_info,struct block_device *bdev,sector_t start,unsigned long rw,unsigned int size);
int rw_cache_writeback(struct rw_cache_info *ca_info,unsigned long limit_cluster);

