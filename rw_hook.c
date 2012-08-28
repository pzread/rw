#include<linux/blkdev.h>
#include<linux/kthread.h>
#include<asm/atomic.h>

#include"rw.h"
#include"rw_hook.h"

void rw_hook_init(){
    int i;

    rw_hook_info_cachep = kmem_cache_create("rw_hook_info_cachep",sizeof(struct rw_hook_info),0,0,NULL);
    hook_bio_info_cachep = kmem_cache_create("hook_bio_info_cachep",sizeof(struct hook_bio_info),0,0,NULL);

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
    hook_info->ori_bdev = bdget_disk(gd,0);
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
    struct rw_cache_info *ca_info;
    unsigned long scan_delay;
    unsigned long wb_limit;

    struct file *tty;
    mm_segment_t old_fs;
    char bar_str[64];
    char out_str[128];

    hook_info = (struct rw_hook_info*)data;
    ca_info = hook_info->ca_info;
    scan_delay = 0;
    while(true){
	if(rw_reboot_flag == true){
	    hook_info->ori_gd->queue->make_request_fn = hook_info->ori_make;

	    pr_alert("RW:Wait for pending requests\n");

	    while(atomic_read(&hook_info->pending_count) > 0){
		schedule_timeout_interruptible(1 * HZ);
	    }

	    wb_limit = atomic64_read(&ca_info->dirty_count) / 50UL + 1UL;
	    pr_alert("RW:Begin write-back %lu\n",wb_limit);

	    tty = filp_open("/dev/tty0",O_RDWR,0);
	    old_fs = set_fs(KERNEL_DS);
	    tty->f_op->write(tty,"\n",2,NULL);

	    for(i = 0;i < 50;i++){
		bar_str[i] = '-';
	    }
	    bar_str[50] = '\0';

	    for(i = 0;i < 50;i++){
		sprintf(out_str,"\rRW:Write-back [%s]  %3d%%",bar_str,i * 2);
		tty->f_op->write(tty,out_str,strlen(out_str),NULL);

		//Careful, free_limit always should be 0.
		rw_cache_scan(ca_info,0,wb_limit,CACHE_WRITEBACK_FORCE);

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

	scan_delay++;
	if((scan_delay % 60UL) == 0){
	    rw_cache_scan(ca_info,1048576,1048576,0);

	    pr_alert("\n%lu %lu\n",scan_delay,atomic64_read(&ca_info->cache_size));
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
    struct rw_cache_info *ca_info;
    int rw;
    struct hook_bio_info *bio_info = NULL;
    struct bio_vec *bv;
    int bv_i;

    sector_t start;
    unsigned int remain;
    unsigned long addr;
    unsigned int idx;
    unsigned int offset;
    bool need_lookup;

    struct rw_cache_cluster *ca_cluster = NULL;
    u8 *sector;
    unsigned int wait_remain;

    hook_info = hook_info_lookup(bio->bi_bdev->bd_disk);
    if(bio->bi_size == 0){
	hook_info->ori_make(q,bio);
	return;
    }
    ca_info = hook_info->ca_info;

    rw = bio_data_dir(bio);
    bio_info = kmem_cache_alloc(hook_bio_info_cachep,GFP_ATOMIC);
    atomic_set(&bio_info->remain,bio->bi_size);
    bio_info->ori_bio = bio;
    bio_info->hook_info = hook_info;

    atomic_inc(&hook_info->pending_count);

    start = bio->bi_sector;
    remain = bio->bi_size;
    addr = ((start & ~(CACHE_CLUSTER_SIZE - 1UL)) << 9UL);
    idx = start & (CACHE_CLUSTER_SIZE - 1UL);
    need_lookup = true;
    wait_remain = 0;

    bio_for_each_segment(bv,bio,bv_i){
	for(offset = 0;offset < bv->bv_len;offset += 512){
	    if(need_lookup == true){
		ca_cluster = rw_cache_get_cluster(ca_info,addr);
		need_lookup = false;
	    }

	    atomic_add_unless(&ca_cluster->used[idx],1,CACHE_CLUSTER_USED_MAX);

	    if(rw == 1){

		spin_lock_irq(&ca_cluster->lock);

		sector = rcu_dereference(ca_cluster->sector[idx]);
		if(sector == NULL){
		    rcu_assign_pointer(ca_cluster->sector[idx],rw_cache_alloc_sector(ca_info));
		    ca_cluster->bitmap |= (1 << idx);
		}

		if((ca_cluster->dirty & (1 << idx)) == 0){
		    atomic64_inc(&ca_info->dirty_count);
		}
		ca_cluster->dirty |= (1 << idx);
		memcpy(ca_cluster->sector[idx],page_address(bv->bv_page) + bv->bv_offset + offset,512); 

		spin_unlock_irq(&ca_cluster->lock);

		hook_end_bio(bio_info,512);
	    }else{

		rcu_read_lock();

		sector = rcu_dereference(ca_cluster->sector[idx]);
		if(sector != NULL && (ca_cluster->bitmap & (1 << idx)) != 0){
		    memcpy(page_address(bv->bv_page) + bv->bv_offset + offset,ca_cluster->sector[idx],512); 
		    
		    rcu_read_unlock();
		    
		    hook_end_bio(bio_info,512);
		}else{

		    rcu_read_unlock();

		    spin_lock_irq(&ca_cluster->lock);

		    rw_cache_wait_sector(ca_cluster,idx,page_address(bv->bv_page) + bv->bv_offset + offset,hook_loaded,bio_info);
		    sector = rcu_dereference(ca_cluster->sector[idx]);
		    if(sector == NULL){
			rcu_assign_pointer(ca_cluster->sector[idx],rw_cache_alloc_sector(ca_info));
			ca_cluster->bitmap &= ~(1 << idx);
			ca_cluster->dirty &= ~(1 << idx);
			atomic_set(&ca_cluster->used[idx],CACHE_CLUSTER_USED_INIT);

			spin_unlock_irq(&ca_cluster->lock);

			wait_remain += 512;
			goto skip_submit;
		    }else{

			spin_unlock_irq(&ca_cluster->lock);

		    }
		}
	    }

	    if(wait_remain > 0){
		rw_cache_load(ca_info,bio->bi_bdev,start - (sector_t)(wait_remain >> 9),wait_remain);
		wait_remain = 0;
	    }

skip_submit:

	    start += 1UL;
	    remain -= 512;
	    addr = ((start & ~(CACHE_CLUSTER_SIZE - 1UL)) << 9UL);
	    idx = start & (CACHE_CLUSTER_SIZE - 1UL);
	    if(idx == 0){
		need_lookup = true;
	    }
	}
    }

    if(wait_remain > 0){
	rw_cache_load(ca_info,bio->bi_bdev,start - (sector_t)(wait_remain >> 9),wait_remain);
    }
}
static void hook_loaded(void *loaded_private){
    struct hook_bio_info *bio_info;

    bio_info = (struct hook_bio_info*)loaded_private;
    hook_end_bio(bio_info,512);
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

