#include<linux/blkdev.h>
#include<linux/kthread.h>
#include<asm/atomic.h>

#include"rw.h"
#include"rw_hook.h"

void rw_hook_init(){
    int i;

    rw_hook_info_cachep = kmem_cache_create("rw_hook_info_cachep",sizeof(struct rw_hook_info),0,0,NULL);
    hook_bio_info_cachep = kmem_cache_create("hook_bio_info_cachep",sizeof(struct hook_bio_info),0,0,NULL);
    hook_loaded_info_cachep = kmem_cache_create("hook_loaded_info_cachep",sizeof(struct hook_loaded_info),0,0,NULL);

    for(i = 0;i < HOOK_INFO_HASHSIZE;i++){
	INIT_HLIST_HEAD(&hook_info_hash[i]);
    }

    atomic_set(&hook_count,0);
}

int rw_hook_install(struct gendisk *gd){
    struct rw_hook_info *hook_info;
    unsigned int hash;

    hook_info = kmem_cache_alloc(rw_hook_info_cachep,GFP_ATOMIC);
    
    hash = (unsigned int)((unsigned long)gd % HOOK_INFO_HASHSIZE);
    
    spin_lock(&hook_info_hash_lock);

    hlist_add_head(&hook_info->node,&hook_info_hash[hash]);

    spin_unlock(&hook_info_hash_lock);

    hook_info->ori_gd = gd;
    hook_info->ori_make = gd->queue->make_request_fn;
    hook_info->ca_info = rw_cache_create(hook_info);
    hook_info->watcher = kthread_run(hook_watcher,hook_info,"rw_hook_watcher");
    atomic_set(&hook_info->pending_count,0);

    atomic_inc(&hook_count);

    gd->queue->make_request_fn = hook_make;

    return 0;
}
static int hook_watcher(void *data){
    int i;

    struct rw_hook_info *hook_info;
    int scan_delay;
    unsigned long scan_start;
    unsigned long scan_next;
    unsigned long wb_limit;

    struct file *tty;
    mm_segment_t old_fs;
    char bar_str[64];
    char out_str[128];

    hook_info = (struct rw_hook_info*)data;
    scan_start = 0;
    scan_delay = 0;
    while(true){
	if(rw_reboot_flag == true){
	    hook_info->ori_gd->queue->make_request_fn = hook_info->ori_make;

	    pr_alert("RW:Wait for pending requests\n");

	    while(atomic_read(&hook_info->pending_count) > 0){
		schedule_timeout_interruptible(1 * HZ);
	    }

	    wb_limit = atomic64_read(&hook_info->ca_info->dirty_count) / 50UL + 1UL;
	    pr_alert("RW:Begin write-back %lu\n",wb_limit);

	    tty = filp_open("/dev/tty0",O_RDWR,0);
	    old_fs = set_fs(KERNEL_DS);
	    tty->f_op->write(tty,"\n",2,NULL);

	    for(i = 0;i < 50;i++){
		bar_str[i] = '-';
	    }
	    bar_str[50] = '\0';

	    scan_start = 0;
	    for(i = 0;i < 50;i++){
		sprintf(out_str,"\rRW:Write-back [%s]  %3d%%",bar_str,i * 2);
		tty->f_op->write(tty,out_str,strlen(out_str),NULL);

		//Careful, free_limit always should be 0.
		rw_cache_scan(hook_info->ca_info,scan_next,0,wb_limit,CACHE_WRITEBACK_FORCE,&scan_next);
		scan_start = scan_next;

		bar_str[i] = '#';
	    }

	    tty->f_op->write(tty,"\n",2,NULL);
	    set_fs(old_fs);
	    filp_close(tty,0);

	    pr_alert("RW:Finish write-back\n");

	    if(atomic_dec_and_test(&hook_count)){
		complete(&rw_reboot_wait);	
	    }

	    break;
	}

	if(scan_delay == 600){
	    rw_cache_scan(hook_info->ca_info,scan_start,1048576,131072,0,&scan_next);
	    scan_start = scan_next;
	    scan_delay = 0;
	}else{
	    scan_delay++;
	}

	schedule_timeout_interruptible(1 * HZ);
    }

    do_exit(0);
    return 0;
}

static struct rw_hook_info* hook_info_lookup(struct gendisk *gd){
    unsigned int hash;
    struct rw_hook_info *hook_info;
    struct hlist_node *node;

    hash = (unsigned int)((unsigned long)gd % HOOK_INFO_HASHSIZE);
    hook_info = NULL;

    rcu_read_lock();

    hlist_for_each_entry_rcu(hook_info,node,&hook_info_hash[hash],node){
	if(hook_info->ori_gd == gd){
	    break;
	}
	hook_info = NULL;
    }

    rcu_read_unlock();

    return hook_info;
}

static void hook_make(struct request_queue *q, struct bio *bio){
    struct rw_hook_info *hook_info;
    int rw;
    struct hook_bio_info *bio_info = NULL;
    struct bio_vec *bv;
    int bv_i;

    sector_t sector;
    unsigned int remain;
    unsigned long addr;
    unsigned int idx;
    unsigned int offset;
    bool need_lookup;
    bool need_lock;

    struct rw_cache_cluster *ca_cluster = NULL;
    struct hook_loaded_info *loaded_info;
    unsigned int wait_remain;

    hook_info = hook_info_lookup(bio->bi_bdev->bd_disk);
    if(bio->bi_size == 0){
	hook_info->ori_make(q,bio);
	return;
    }

    rw = bio_data_dir(bio);
    bio_info = kmem_cache_alloc(hook_bio_info_cachep,GFP_ATOMIC);
    atomic_set(&bio_info->remain,bio->bi_size);
    bio_info->ori_bio = bio;
    bio_info->hook_info = hook_info;

    atomic_inc(&hook_info->pending_count);

    sector = bio->bi_sector;
    remain = bio->bi_size;
    addr = ((sector & ~(CACHE_CLUSTER_SIZE - 1UL)) << 9UL);
    idx = sector & (CACHE_CLUSTER_SIZE - 1UL);
    need_lookup = true;
    need_lock = true;
    wait_remain = 0;

    bio_for_each_segment(bv,bio,bv_i){
	for(offset = 0;offset < bv->bv_len;offset += 512){
	    if(need_lookup == true){
		if(need_lock == false){

		    spin_unlock_irq(&ca_cluster->lock);

		}

		spin_lock_irq(&hook_info->ca_info->ca_lock);

		ca_cluster = rw_cache_get_cluster(hook_info->ca_info,addr);
		need_lookup = false;

		spin_unlock_irq(&hook_info->ca_info->ca_lock);

		spin_lock_irq(&ca_cluster->lock);

		need_lock = false;
	    }else if(need_lock == true){
		
		spin_lock_irq(&ca_cluster->lock);

		need_lock = false;
	    }

	    ca_cluster->used |= (1 << idx);

	    if((ca_cluster->bitmap & (1 << idx)) != 0){
		if(rw == 1){
		    if((ca_cluster->dirty & (1 << idx)) == 0){
			atomic64_inc(&hook_info->ca_info->dirty_count);
		    }
		    ca_cluster->dirty |= (1 << idx);
		    memcpy(ca_cluster->sector[idx],page_address(bv->bv_page) + bv->bv_offset + offset,512); 
		}else{
		    memcpy(page_address(bv->bv_page) + bv->bv_offset + offset,ca_cluster->sector[idx],512); 
		}

		spin_unlock_irq(&ca_cluster->lock);

		need_lock = true;
		hook_end_bio(bio_info,512);
	    }else if(rw == 1){
		if(ca_cluster->sector[idx] == NULL){
		    ca_cluster->sector[idx] = rw_cache_alloc_sector(hook_info->ca_info);
		    ca_cluster->bitmap |= (1 << idx);
		}

		if((ca_cluster->dirty & (1 << idx)) == 0){
		    atomic64_inc(&hook_info->ca_info->dirty_count);
		}
		ca_cluster->dirty |= (1 << idx);
		memcpy(ca_cluster->sector[idx],page_address(bv->bv_page) + bv->bv_offset + offset,512); 

		spin_unlock_irq(&ca_cluster->lock);

		need_lock = true;
		hook_end_bio(bio_info,512);
	    }else{
		loaded_info = kmem_cache_alloc(hook_loaded_info_cachep,GFP_ATOMIC);
		loaded_info->bio_info = bio_info;

		rw_cache_wait_sector(ca_cluster,idx,page_address(bv->bv_page) + bv->bv_offset + offset,hook_loaded,loaded_info);

		if(ca_cluster->sector[idx] == NULL){
		    ca_cluster->sector[idx] = rw_cache_alloc_sector(hook_info->ca_info);

		    wait_remain += 512;
		    goto skip_submit;
		}else{

		    spin_unlock_irq(&ca_cluster->lock);

		    need_lock = true;
		}
	    }

	    if(wait_remain > 0){
		rw_cache_load(hook_info->ca_info,bio->bi_bdev,sector - (sector_t)(wait_remain >> 9),bio->bi_rw,wait_remain);
		wait_remain = 0;
	    }

skip_submit:

	    sector += 1UL;
	    remain -= 512;
	    addr = ((sector & ~(CACHE_CLUSTER_SIZE - 1UL)) << 9UL);
	    idx = sector & (CACHE_CLUSTER_SIZE - 1UL);
	    if(idx == 0){
		atomic_dec(&ca_cluster->refcount);
		need_lookup = true;
	    }
	}
    }
    if(need_lock == false){

	spin_unlock_irq(&ca_cluster->lock);
    
    }
    if(need_lookup == false){
	atomic_dec(&ca_cluster->refcount);
    }

    if(wait_remain > 0){
	rw_cache_load(hook_info->ca_info,bio->bi_bdev,sector - (sector_t)(wait_remain >> 9),bio->bi_rw,wait_remain);
    }
}

static void hook_loaded(void *loaded_private){
    struct hook_loaded_info *loaded_info;

    loaded_info = (struct hook_loaded_info*)loaded_private;
    hook_end_bio(loaded_info->bio_info,512);
    kmem_cache_free(hook_loaded_info_cachep,loaded_info);
}
static void hook_end_bio(struct hook_bio_info *bio_info,unsigned int size){
    struct bio * ori_bio;

    if(atomic_sub_and_test(size,&bio_info->remain)){
	ori_bio = bio_info->ori_bio;

	ori_bio->bi_sector += (sector_t)(ori_bio->bi_size >> 9);
	ori_bio->bi_size = 0;
	ori_bio->bi_flags |= 1;

	bio_endio(ori_bio,0);
	kmem_cache_free(hook_bio_info_cachep,bio_info);

	atomic_dec(&bio_info->hook_info->pending_count);
    }
}

