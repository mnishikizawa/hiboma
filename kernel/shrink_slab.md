## shrink_slab

 * slabキャッシュを破棄する
   * inode_cache, dentry が大半を占める
   * kswapd, 任意のプロセス, 割り込みコンテキスト? の alloc_page 群から呼び出される
 * node と zone 

## SEE ALSO

 * https://github.com/hiboma/hiboma/blob/master/kernel/SReclaimable.md
 * https://github.com/hiboma/hiboma/blob/master/kernel/dentry_cache.md
 * https://github.com/hiboma/hiboma/blob/master/kernel/swappiness.md
   * shrink_list 周りとごっちゃにしないように

## alloc_page を利用する API

 * pgd_alloc
   * __get_free_pages
   * fork(2) で mm_struct の .pgd を初期化される際に呼ばれる ( mm_alloc_pgd )
     * コケたら -ENOMEM
     * mm_struct は kmem_cache_alloc を使っていた ( allocate_mm )
 * pud_alloc_one, pmd_alloc_one, pte_alloc_one, __pte_alloc
   * get_zeroed_page
     * __get_free_pages
       * alloc_pages
 * page_fault
   * do_page_fault
     * __do_page_fault
       * handle_mm_fault
         * pud_alloc_one, pmd_alloc_one, __pte_alloc
         * handle_pte_fault
            * alloc_zeroed_user_highpage_movable

 * ページフォルトが起きた際に PUD, PMD, PTE のページが無ければ都度割り当てる
   * PGD は fork した際に mm->pgd で確保されていて必ず存在する?

## alloc_page 群

 * alloc_page_buffers
   * バッファ用のページ ( struct buffer_head *) を割り当てる (__getblk)
   * __bread_slow で submit_bh で bio を発行 -> wait_on_buffer(TASK_UNINTERRUPTIBLE) I/O完了を待つ
 * alloc_page_vma
   * vm_area_struct 用のページを割り当てる
   * alloc_page_interleave __alloc_pages_nodemask のいずれかを呼んで page を確保している
 * alloc_pages_current
   * NUMA な構成の場合に current プロセスのメモリポリシーに従ってメモリを配置する
   * alloc_page_interleave もしくは __alloc_pages_nodemask を呼ぶ
 * alloc_page_interleave
   * NUMA で interleave するポリシーになるように page を割り当てる
   * __alloc_pages を呼ぶ

## __alloc_pages 群

node の選択
zone の選択
zone_water_mark

 * __alloc_pages
   * nodemask_t を NULL 指定で __alloc_pages_nodemask を呼ぶだけのラッパー
 * __alloc_pages_nodemask
   * get_page_from_freelist
     * freelist からページを確保できなかったら __alloc_pages_slowpath を呼ぶ
     * zone_reclaim で zone ごとに reclaim できるページを探す
       * __zone_reclaim
         * **shrink_zone**
           * shrink_mem_cgroup_zone
             * shrink_list
               * shrink_active_list
               * shrink_inactive_list
                 * reclaim したページを返す
         * **shrink_slab**
   * **__alloc_pages_slowpath**
     * wake_all_kswapd で kswapd を起床させておく
       * __GFP_NO_KSWAPD が立ってない場合だけ
     * __alloc_pages_direct_compact
     * __alloc_pages_direct_reclaim
       * try_to_free_pages
         * do_try_to_free_pages
           * wakeup_flusher_threads
             * __bdi_start_writeback
               * dirty なページを書き出すスレッドを起床させる
               * bdi_queue_work
     * __alloc_pages_high_priority
     * __alloc_pages_may_oom
     * get_page_from_freelist もういっぺん最後に試してページを確保できないか試す
       * zone_reclaim
         * __zone_reclaim
           * **vm_swappiness** 
           * **shrink_slab**
     * page 割り当てできなかったら `pr_warning("%s: page allocation failure. order:%d, mode:0x%x\n"`
       * __GFP_NOWARN が立ってない場合にだけ pr_warning 出る

## get_page_from_freelist

   * shrink_mem_cgroup_zone
     * shrink_list
 * shrink_zone
 * shrink_slab

#### freelist の対象となるページ

zone ごとに以下を見る

 * memory compaction で確保
   * zone_reclaim_compact
 * NR_INACTIVE_FILE, NR_ACTIVE_FILE で NR_FILE_MAPPED の数を引いたもの
 * shrink_zone
   * mem_cgroup
 * shrink_slab

## try_to 群

 * try_to_free_pages
 * try_to_free_swap
 * try_to_free_buffers

buffer 用のページを割り当てる際にも shrink_slab を呼ぶケースがある

```
alloc_page_buffers
free_more_memory
try_to_release_page
do_try_to_free_pages
 ...
```

## __zone_reclaim

 * NR_SLAB_RECLAIMABLE の数値をスキャンすべきエントリ数に指定して shrink_slab を投げる
```c
static int __zone_reclaim(struct zone *zone, gfp_t gfp_mask, unsigned int order)

//...

	slab_reclaimable = zone_page_state(zone, NR_SLAB_RECLAIMABLE);
	if (slab_reclaimable > zone->min_slab_pages) {
		/*
		 * shrink_slab() does not currently allow us to determine how
		 * many pages were freed in this zone. So we take the current
		 * number of slab pages and shake the slab until it is reduced
		 * by the same nr_pages that we used for reclaiming unmapped
		 * pages.
		 *
		 * Note that shrink_slab will free memory on all zones and may
		 * take a long time.
		 */
		while (shrink_slab(sc.nr_scanned, gfp_mask, order) &&
			zone_page_state(zone, NR_SLAB_RECLAIMABLE) >
				slab_reclaimable - nr_pages)
			;

		/*
		 * Update nr_reclaimed by the number of slab pages we
		 * reclaimed from this zone.
		 */
		sc.nr_reclaimed += slab_reclaimable -
			zone_page_state(zone, NR_SLAB_RECLAIMABLE);
	}
```
## kswapd

__alloc_pages_slowpath -> wake_all_kswapd -> wakeup_kswapd で起床する

 * kswapd
 * balance_pgdat
   * free_pges <= high_wmark_pages(zone).
     * highmem -> normal -> DMA の順番でノード
