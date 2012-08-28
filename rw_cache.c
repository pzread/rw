#include<linux/blkdev.h>

#include"rw.h"
#include"rw_cache.h"

void rw_cache_init(){
    rw_cache_info_cachep = kmem_cache_create("rw_cache_info_cachep",sizeof(struct rw_cache_info),0,0,NULL);
    rw_cache_cluster_cachep = kmem_cache_create("rw_cache_cluster_cachep",sizeof(struct rw_cache_cluster),0,0,NULL);
    rw_wait_sector_cachep = kmem_cache_create("rw_wait_sector_cachep",sizeof(struct rw_wait_sector),0,0,NULL);
    cache_sector_cachep = kmem_cache_create("cache_sector_cachep",512,0,0,NULL);
    cache_req_info_cachep = kmem_cache_create("cache_req_info_cachep",sizeof(struct cache_req_info),0,0,NULL);
    cache_freeback_info_cachep = kmem_cache_create("cache_freeback_info_cachep",sizeof(struct cache_freeback_info),0,0,NULL);
    cache_writeback_info_cachep = kmem_cache_create("cache_writeback_info_cachep",sizeof(struct cache_writeback_info),0,0,NULL);
}

struct rw_cache_info* rw_cache_create(struct rw_hook_info *hook_info){
    struct rw_cache_info *ca_info;

    ca_info = kmem_cache_alloc(rw_cache_info_cachep,GFP_ATOMIC);
    spin_lock_init(&ca_info->ca_lock);
    INIT_RADIX_TREE(&ca_info->ca_root,GFP_ATOMIC);
    ca_info->hook_info = hook_info;
    atomic64_set(&ca_info->cache_size,0);
    atomic64_set(&ca_info->dirty_count,0);
    ca_info->dirty_list = NULL;
    ca_info->fb_start = 0;
    ca_info->wb_start = 0;

    return ca_info;
}

struct rw_cache_cluster* rw_cache_get_cluster(struct rw_cache_info *ca_info,unsigned long addr){
    int i;
    struct rw_cache_cluster *ca_cluster;

    rcu_read_lock();

    ca_cluster = radix_tree_lookup(&ca_info->ca_root,addr);
    
    rcu_read_unlock();
    
    if(ca_cluster == NULL){

	spin_lock_irq(&ca_info->ca_lock);

	if((ca_cluster = radix_tree_lookup(&ca_info->ca_root,addr)) == NULL){
	    ca_cluster = kmem_cache_alloc(rw_cache_cluster_cachep,GFP_ATOMIC);
	    for(i = 0;i < CACHE_CLUSTER_SIZE;i++){
		ca_cluster->sector[i] = NULL;
		atomic_set(&ca_cluster->used[i],CACHE_CLUSTER_USED_INIT);
	    }
	    ca_cluster->bitmap = 0;
	    ca_cluster->dirty = 0;
	    spin_lock_init(&ca_cluster->lock);
	    ca_cluster->start = (addr >> 9UL);
	    ca_cluster->wait_list = NULL;

	    radix_tree_insert(&ca_info->ca_root,addr,ca_cluster);
	}

	spin_unlock_irq(&ca_info->ca_lock);

    }

    return ca_cluster;
}

u8* rw_cache_alloc_sector(struct rw_cache_info *ca_info){
    atomic64_add(512,&ca_info->cache_size);
    return kmem_cache_alloc(cache_sector_cachep,GFP_ATOMIC);
}

int rw_cache_wait_sector(struct rw_cache_cluster *ca_cluster,unsigned int idx,u8 *buffer,rw_loaded_fn loaded_fn,void *loaded_private){
    struct rw_wait_sector *wait_sector;

    wait_sector = kmem_cache_alloc(rw_wait_sector_cachep,GFP_ATOMIC);
    wait_sector->idx = idx;
    wait_sector->buffer = buffer;
    wait_sector->loaded_fn = loaded_fn;
    wait_sector->loaded_private = loaded_private;

    wait_sector->next = ca_cluster->wait_list;
    ca_cluster->wait_list = wait_sector;

    return 0;
}

int rw_cache_load(struct rw_cache_info *ca_info,struct block_device *bdev,sector_t start,unsigned int size){
    int i;
    struct cache_req_info *req_info;
    struct bio *new_bio;

    req_info = kmem_cache_alloc(cache_req_info_cachep,GFP_ATOMIC);
    req_info->start = start;
    req_info->size = size;
    req_info->ca_info = ca_info;

    new_bio = bio_alloc(GFP_ATOMIC,((req_info->size - 1) / PAGE_SIZE) + 1); 
    new_bio->bi_bdev = bdev;
    new_bio->bi_sector = req_info->start; 
    new_bio->bi_size = req_info->size;
    new_bio->bi_private = req_info;
    new_bio->bi_end_io = cache_load_endio;
    new_bio->bi_rw = 0;

    new_bio->bi_vcnt = 0;
    for(i = 0;size > 0;i++){
	new_bio->bi_vcnt++;

	new_bio->bi_io_vec[i].bv_page = alloc_pages(GFP_ATOMIC,0);
	new_bio->bi_io_vec[i].bv_offset = 0;
	if(size > PAGE_SIZE){
	    new_bio->bi_io_vec[i].bv_len = PAGE_SIZE;
	    size -= PAGE_SIZE;
	}else{
	    new_bio->bi_io_vec[i].bv_len = size;
	    size = 0;
	}
    }

    ca_info->hook_info->ori_make(bdev->bd_queue,new_bio);

    return 0;
}
static void cache_load_endio(struct bio *bio,int error){
    unsigned long irqflag = 0;

    struct cache_req_info *req_info;
    struct bio_vec *bv;
    int bv_i;

    sector_t sector;
    unsigned int remain;
    unsigned long addr;
    unsigned int idx;
    unsigned int offset;
    bool need_lookup;

    struct rw_cache_cluster *ca_cluster = NULL;
    struct rw_wait_sector *wait_sector;
    struct rw_wait_sector *next;
    struct rw_wait_sector *prev;
    struct rw_wait_sector *check_list;

    req_info = (struct cache_req_info*)bio->bi_private;
    sector = req_info->start;
    remain = req_info->size;
    addr = ((sector & ~(CACHE_CLUSTER_SIZE - 1UL)) << 9UL);
    idx = sector & (CACHE_CLUSTER_SIZE - 1UL);
    need_lookup = true;
    check_list = NULL;

    for(bv_i = 0,bv = bio->bi_io_vec;bv_i < bio->bi_vcnt;bv_i++,bv++){
	for(offset = 0;offset < (bv->bv_offset + bv->bv_len);offset += 512){
	    if(need_lookup == true){

		rcu_read_lock();

		ca_cluster = radix_tree_lookup(&req_info->ca_info->ca_root,addr);

		rcu_read_unlock();

		spin_lock_irqsave(&ca_cluster->lock,irqflag);

	    }

	    next = ca_cluster->wait_list;
	    prev = NULL;
	    while(next != NULL){
		wait_sector = next;

		if(wait_sector->idx != idx){
		    prev = wait_sector;
		    next = wait_sector->next;
		}else{
		    memcpy(wait_sector->buffer,page_address(bv->bv_page) + offset,512);

		    if(prev != NULL){
			prev->next = wait_sector->next;
		    }else{
			ca_cluster->wait_list = wait_sector->next;
		    }
		    next = wait_sector->next;

		    wait_sector->next = check_list;
		    check_list = wait_sector;
		}
	    }

	    memcpy(ca_cluster->sector[idx],page_address(bv->bv_page) + offset,512);
	    ca_cluster->bitmap |= (1 << idx);

	    sector += 1UL;
	    remain -= 512;
	    addr = ((sector & ~(CACHE_CLUSTER_SIZE - 1UL)) << 9UL);
	    idx = sector & (CACHE_CLUSTER_SIZE - 1UL);

	    if(idx == 0){

		spin_unlock_irqrestore(&ca_cluster->lock,irqflag);

		need_lookup = true;
	    }else{
		need_lookup = false;
	    }
	}

	__free_pages(bv->bv_page,0);
    }

    if(need_lookup == false){

	spin_unlock_irqrestore(&ca_cluster->lock,irqflag);

    }

    next = check_list;
    while(next != NULL){
	wait_sector = next;

	wait_sector->loaded_fn(wait_sector->loaded_private);

	next = wait_sector->next;
	kmem_cache_free(rw_wait_sector_cachep,wait_sector);
    }

    kmem_cache_free(cache_req_info_cachep,req_info);
    bio_put(bio);
}

int rw_cache_scan(struct rw_cache_info *ca_info,unsigned long free_limit,unsigned long write_limit,unsigned int flags){
    int i;

    struct rw_cache_cluster **ca_cluster_pool;
    struct rw_cache_cluster *ca_cluster;
    sector_t start;
    unsigned long addr;
    bool restart;
    bool fb_stop;
    struct cache_freeback_info *fb_list;
    struct cache_freeback_info *fb_next;
    struct cache_freeback_info *fb_info;
    bool wb_stop;
    u64 write_st;
    bool write_force;
    int lookup_count;

    struct semaphore bucket;
    atomic_t remain;
    struct completion wait;

    ca_cluster_pool = kmalloc(sizeof(void*) * 4096,GFP_ATOMIC);
    if(ca_info->fb_start < ca_info->wb_start){
	start = ca_info->fb_start;
    }else{
	start = ca_info->wb_start;
    }
    addr = start << 9UL;
    restart = false;
    fb_stop = false;
    fb_list = NULL;
    wb_stop = false;
    write_st = get_jiffies_64();

    if((flags & CACHE_WRITEBACK_FORCE) != 0){
	write_force = true;
    }else{
	write_force = false;
    }

    sema_init(&bucket,16);
    atomic_set(&remain,1);
    init_completion(&wait);

    while(true){

	rcu_read_lock();
	
	lookup_count = radix_tree_gang_lookup(&ca_info->ca_root,(void**)ca_cluster_pool,addr,4096);

	rcu_read_unlock();

	if(lookup_count == 0){
	    start = 0;
	    addr = 0;

	    if(restart == false){
		restart = true;
	    }else{
		if(fb_stop == false){
		    fb_stop = true;
		    ca_info->fb_start = 0;
		}
		if(wb_stop == false){
		    wb_stop = true;
		    ca_info->wb_start = 0;
		}

		break;
	    }
	}else{
	    for(i = 0;i < lookup_count;i++){
		ca_cluster = ca_cluster_pool[i];

		spin_lock(&ca_cluster->lock);

		start = ca_cluster->start;

		if(fb_stop == false){
		    if((start >= ca_info->fb_start) ^ restart){
			cache_freeback(ca_info,ca_cluster,&free_limit,&fb_list);

			if(free_limit == 0){
			    fb_stop = true;
			    ca_info->fb_start = start;
			}
		    }else if(restart == true){
			fb_stop = true;
			ca_info->fb_start = start;
		    }
		}
		if(wb_stop == false){
		    if((start >= ca_info->wb_start) ^ restart){
			cache_writeback(ca_info,ca_cluster,&write_limit,&bucket,&remain,&wait);

			if(write_limit == 0 || ((get_jiffies_64() - write_st) > 3 * HZ && write_force == false)){
			    wb_stop = true;
			    ca_info->wb_start = start;
			}
		    }else if(restart == true){
			wb_stop = true;
			ca_info->wb_start = start;
		    }
		}

		spin_unlock(&ca_cluster->lock);

		if(fb_stop == true && wb_stop == true){
		    goto out_lookup;
		}

		addr = (start + CACHE_CLUSTER_SIZE) << 9UL;
	    }
	}
    }

out_lookup:

    kfree(ca_cluster_pool);

    synchronize_rcu();

    fb_next = fb_list;
    while(fb_next != NULL){
	fb_info = fb_next;

	atomic64_sub(512,&ca_info->cache_size);
	kmem_cache_free(cache_sector_cachep,fb_info->sector);

	fb_next = fb_info->next;
	kmem_cache_free(cache_freeback_info_cachep,fb_info);
    }

    if(!atomic_dec_and_test(&remain)){
	wait_for_completion_interruptible(&wait);
    }

    pr_alert("\n  %lu %lu %lu %lu\n",free_limit,write_limit,ca_info->fb_start,ca_info->wb_start);

    return 0;
}
static void cache_freeback(struct rw_cache_info *ca_info,struct rw_cache_cluster *ca_cluster,unsigned long *free_limit,struct cache_freeback_info **fb_list){
    int idx;
    u8* sector;
    struct cache_freeback_info *fb_info;

    for(idx = 0;idx < CACHE_CLUSTER_SIZE && *free_limit > 0;idx++){
	sector = rcu_dereference(ca_cluster->sector[idx]);
	if(sector != NULL && (ca_cluster->bitmap & (1 << idx)) != 0){
	    if(!atomic_add_unless(&ca_cluster->used[idx],-1,0) && (ca_cluster->dirty & (1 << idx)) == 0){
		rcu_assign_pointer(ca_cluster->sector[idx],NULL);
		
		fb_info = kmem_cache_alloc(cache_freeback_info_cachep,GFP_ATOMIC);
		fb_info->sector = sector;
		fb_info->next = *fb_list;
		*fb_list = fb_info;

		(*free_limit)--;
	    }
	}
    }
}
static void cache_writeback(struct rw_cache_info *ca_info,struct rw_cache_cluster *ca_cluster,unsigned long *write_limit,struct semaphore *bucket,atomic_t *remain,struct completion *wait){
    int i;

    unsigned int idx;
    unsigned int idx_st;
    unsigned int size;
    unsigned int offset;
    struct bio *new_bio;
    struct cache_writeback_info *wb_info;
    
    idx_st = 0;
    size = 0;

    for(idx = 0;idx < CACHE_CLUSTER_SIZE && *write_limit > 0;idx++){
	if((ca_cluster->dirty & (1 << idx)) != 0){
	    if(size == 0){
		idx_st = idx;
	    }
	    size += 512;
	    atomic64_dec(&ca_info->dirty_count);

	    (*write_limit)--;

	    if(idx < (CACHE_CLUSTER_SIZE - 1) && *write_limit > 0){
		continue;
	    }
	}

	if(size > 0){
	    wb_info = kmem_cache_alloc(cache_writeback_info_cachep,GFP_ATOMIC);
	    wb_info->bucket = bucket;
	    wb_info->remain = remain;
	    wb_info->wait = wait;

	    new_bio = bio_alloc(GFP_ATOMIC,((size - 1) / PAGE_SIZE) + 1); 
	    new_bio->bi_bdev = ca_info->hook_info->ori_bdev;
	    new_bio->bi_sector = ca_cluster->start + (sector_t)idx_st; 
	    new_bio->bi_size = size;
	    new_bio->bi_private = wb_info;
	    new_bio->bi_end_io = cache_writeback_endio;
	    new_bio->bi_rw = REQ_WRITE;

	    new_bio->bi_vcnt = 0;
	    for(i = 0;size > 0;i++){
		new_bio->bi_vcnt++;

		new_bio->bi_io_vec[i].bv_page = alloc_pages(GFP_ATOMIC,0);
		new_bio->bi_io_vec[i].bv_offset = 0;
		if(size > PAGE_SIZE){
		    new_bio->bi_io_vec[i].bv_len = PAGE_SIZE;
		    size -= PAGE_SIZE;
		}else{
		    new_bio->bi_io_vec[i].bv_len = size;
		    size = 0;
		}

		for(offset = 0;offset < new_bio->bi_io_vec[i].bv_len;offset += 512){
		    memcpy(page_address(new_bio->bi_io_vec[i].bv_page) + offset,ca_cluster->sector[idx_st],512);
		    ca_cluster->dirty &= ~(1 << idx_st);
		    idx_st++;
		}
	    }

	    spin_unlock(&ca_cluster->lock);

	    down_interruptible(bucket);

	    atomic_inc(remain);
	    ca_info->hook_info->ori_make(ca_info->hook_info->ori_bdev->bd_queue,new_bio);

	    spin_lock(&ca_cluster->lock);

	}
    }
}
static void cache_writeback_endio(struct bio *bio,int error){
    int bv_i;
    struct cache_writeback_info *wb_info;

    for(bv_i = 0;bv_i < bio->bi_vcnt;bv_i++){
	__free_pages(bio->bi_io_vec[bv_i].bv_page,0);
    }
    bio_put(bio);

    wb_info = (struct cache_writeback_info*)bio->bi_private;
    up(wb_info->bucket);
    if(atomic_dec_and_test(wb_info->remain)){
	complete(wb_info->wait);
    }
    kmem_cache_free(cache_writeback_info_cachep,wb_info);
}
