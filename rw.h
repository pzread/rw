#define CACHE_CLUSTER_SIZE 16

struct rw_hook_info{
    struct hlist_node node;

    struct gendisk *ori_gd;
    make_request_fn *ori_make;
    struct rw_cache_info *ca_info;
    struct task_struct *watcher;
    atomic_t pending_count;
};

struct rw_cache_info{
    spinlock_t ca_lock;
    struct radix_tree_root ca_root;
    struct rw_hook_info *hook_info;
    atomic_t dirty_count;
    struct rw_cache_cluster *dirty_list;
};
struct rw_cache_cluster{
    u8 *sector[CACHE_CLUSTER_SIZE];
    u16 bitmap;
    u16 dirty;
    spinlock_t lock;
    sector_t start;
    struct rw_cache_cluster *next;
    struct rw_wait_sector *wait_list;
};

typedef void (rw_loaded_fn)(void *);
struct rw_wait_sector{
    struct rw_wait_sector *next;
    unsigned int idx;
    u8 *buffer;
    rw_loaded_fn *loaded_fn;
    void *loaded_private;
};
