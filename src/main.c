/*
 * LiME - Linux Memory Extractor
 * Copyright (c) 2011-2014 Joe Sylve - 504ENSICS Labs
 *
 *
 * Author:
 * Joe Sylve       - joe.sylve@gmail.com, @jtsylve
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */


#include "lime.h"
#include <linux/hyplet.h>
#include <linux/smp.h>
#include <linux/delay.h>

// This file
static int write_lime_header(struct resource *);
static ssize_t write_padding(size_t);
static void write_range(struct resource *);
static int init(void);
ssize_t write_vaddr(void *, size_t);
int setup(void);
void cleanup(void);

// External
extern void turn_on_acq(void);

extern int write_vaddr_tcp(void *, size_t);
extern int setup_tcp(void);
extern void cleanup_tcp(void);

extern int write_vaddr_disk(void *, size_t);
extern int setup_disk(void);
extern void cleanup_disk(void);

extern int ldigest_init(void);
extern int ldigest_update(void *, size_t);
extern int ldigest_final(void);

static char * format = 0;
static int mode = 0;
static int method = 0;
static unsigned int sleep_time = 0; /* module parameter to control time in ms that lime sleeps every iteration of the tranmistion loop */
static char * zero_page;

char * path = 0;
int dio = 0;
int port = 0;
int localhostonly = 0;

char * digest = 0;
int compute_digest = 0;

// microvisor stuff
struct LimePagePool* pool =  NULL;
hyp_memory_protocol page_buffer = {0}; // should zero this struct

extern struct resource iomem_resource;

module_param(path, charp, S_IRUGO);
module_param(dio, int, S_IRUGO);
module_param(format, charp, S_IRUGO);
module_param(localhostonly, int, S_IRUGO);
module_param(digest, charp, S_IRUGO);
module_param(sleep_time, uint, S_IRUGO); // sleep time for transmition loop, defaults to 0 if not specified

#ifdef LIME_SUPPORTS_TIMING
long timeout = 1000;
module_param(timeout, long, S_IRUGO);
#endif

#define RETRY_IF_INTURRUPTED(f) ({ \
    ssize_t err; \
    do { err = f; } while(err == -EAGAIN || err == -EINTR); \
    err; \
})

int init_module (void)
{
    if(!path) {
        DBG("No path parameter specified");
        return -EINVAL;
    }

    if(!format) {
        DBG("No format parameter specified");
        return -EINVAL;
    }

    DBG("Parameters");
    DBG("  PATH: %s", path);
    DBG("  DIO: %u", dio);
    DBG("  FORMAT: %s", format);
    DBG("  LOCALHOSTONLY: %u", localhostonly);
    DBG("  DIGEST: %s", digest);
    DBG("  sleep_time: %u", sleep_time);

#ifdef LIME_SUPPORTS_TIMING
    DBG("  TIMEOUT: %lu", timeout);
#endif

    zero_page = kzalloc(PAGE_SIZE, GFP_KERNEL);

    if (!strcmp(format, "raw")) mode = LIME_MODE_RAW;
    else if (!strcmp(format, "lime")) mode = LIME_MODE_LIME;
    else if (!strcmp(format, "padded")) mode = LIME_MODE_PADDED;
    else {
        DBG("Invalid format parameter specified.");
        return -EINVAL;
    }

    method = (sscanf(path, "tcp:%d", &port) == 1) ? LIME_METHOD_TCP : LIME_METHOD_DISK;
    if (digest) compute_digest = LIME_DIGEST_COMPUTE;
    return init();
}

static int init() {
    struct resource *p;
    int err = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
    resource_size_t p_last = -1;
#else
    __PTRDIFF_TYPE__ p_last = -1;
#endif

    DBG("Initializing Dump...");

    if((err = setup())) {
        DBG("Setup Error");
        cleanup();
        return err;
    }

    if(compute_digest == LIME_DIGEST_COMPUTE)
        compute_digest = ldigest_init();

    /* start microvisor(and inderectly initialize the pool) and acquire the pool*/    
    
    turn_on_acq();
    pool = (hyplet_get_vm())->limePool;

    printk(KERN_DEBUG "lime pool = %p", (void*)pool);

        
    for (p = iomem_resource.child; p ; p = p->sibling) {

        if (strcmp(p->name, LIME_RAMSTR))
            continue;

        /* Transmiting the lime header */
        if (mode == LIME_MODE_LIME && (err = write_lime_header(p))) {
            DBG("Error writing header 0x%lx - 0x%lx", (long) p->start, (long) p->end);
           break;
        } else if (mode == LIME_MODE_PADDED && (err = write_padding((size_t) ((p->start - 1) - p_last)))) {
            DBG("Error writing padding 0x%lx - 0x%lx", (long) p_last, (long) p->start - 1);
           break;
        }

        /* Transmit the RAM range */
        write_range(p);

        p_last = p->end;
    }

    DBG("Memory Dump Complete...");

    cleanup();

    if(compute_digest == LIME_DIGEST_COMPUTE)
        compute_digest = ldigest_final();

    return err;
}

static int write_lime_header(struct resource * res) {
    ssize_t s;

    lime_mem_range_header header;

    memset(&header, 0, sizeof(lime_mem_range_header));
    header.magic = LIME_MAGIC;
    header.version = 1;
    header.s_addr = res->start;
    header.e_addr = res->end;

    s = write_vaddr(&header, sizeof(lime_mem_range_header));

    if (s != sizeof(lime_mem_range_header)) {
        DBG("Error sending header %zd", s);
        return (int) s;
    }

    return 0;
}

static ssize_t write_padding(size_t s) {
    size_t i = 0;
    ssize_t r;

    while(s -= i) {

        i = min((size_t) PAGE_SIZE, s);
        r = write_vaddr(zero_page, i);

        if (r != i) {
            DBG("Error sending zero page: %zd", r);
            return r;
        }
    }

    return 0;
}

static void write_range(struct resource * res) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
    resource_size_t i, is;
#else
    __PTRDIFF_TYPE__ i, is;
#endif
    struct page * p;
    void * v;

    ssize_t s;

#ifdef LIME_SUPPORTS_TIMING
    ktime_t start,end;
#endif

    DBG("Writing range %llx - %llx.", res->start, res->end);

    for (i = res->start; i <= res->end; i += is) {
        /* configure sleep im transmition loop */
        msleep(sleep_time);

#ifdef LIME_SUPPORTS_TIMING
        start = ktime_get_real();
#endif
        p = pfn_to_page((i) >> PAGE_SHIFT);
        is = min((size_t) PAGE_SIZE, (size_t) (res->end - i + 1));

        if (is < PAGE_SIZE) {
            // We can't map partial pages and
            // the linux kernel doesn't use them anyway
            DBG("Padding partial page: vaddr %p size: %lu", (void *) i, (unsigned long) is);
            write_padding(is);
        } else {
            v = kmap(p);
            //If we don't need to compute the digest; lets save some memory 
            //and cycles
            if(compute_digest == LIME_DIGEST_COMPUTE) {
                /* Digest option is NOT relevant for mem_acq purposes */
                void * lv = kmalloc(is, GFP_ATOMIC);
                memcpy(lv, v, is);
                s = write_vaddr(lv, is);
                kfree(lv);
            } else {   
                /*
                foreach slot in pool:
                    if slot not int bitfield:
                        send(phys_addr); send(slot); mark_free(slot)
                if(v not in bitfield):
                    send(v)
                */ 
                size_t index, pool_index;
                int bitfield_index;
                for (pool_index = 0; pool_index < NUM_POOLS; pool_index++)
                {
                    for (index = 0; index < POOL_SIZE; index++)
                    {
                        bitfield_index = phy_addr_to_bitfield_page_index(pool->pools[pool_index][index].phy_addr);
                        if(bitfield_index < 0)
                            printk(KERN_EMERG "bitfield_index < 0 ; phy_addr = %lu\n", pool->pools[pool_index][index].phy_addr);
                        
                        if(pool->pools[pool_index][index].state == LiME_POOL_PAGE_FREE || IS_PAGE_SENT(pool->page_processed, bitfield_index))
                        {
                            /* important to realease unneeded page slots*/
                            if(pool->pools[pool_index][index].state == LiME_POOL_PAGE_OCCUPIED && IS_PAGE_SENT(pool->page_processed, bitfield_index))
                                pool->pools[pool_index][index].state = LiME_POOL_PAGE_FREE;
                            
                            continue; // TODO 'optimization' if(free) calc bitfield index and then if(IS_PAGE_SENT) continue; instead of alwways calculating 
                        }

                        /* send page.phy_addr and page.content */
                        write_vaddr((void*) &(pool->pools[pool_index][index].phy_addr), sizeof(pool->pools[pool_index][index].phy_addr));
                        s = write_vaddr((void*) pool->pools[pool_index][index].hyp_vaddr, is); // TODO: is can probably create bugs, but is not supposed to, check later

                        /* free slot for reusage */                    
                        SET_PAGE_TO_SENT(pool->page_processed, bitfield_index);
                        pool->pools[pool_index][index].state = LiME_POOL_PAGE_FREE;                    

                        if (s < 0) {
                            DBG("Error writing page: vaddr %p ret: %zd.  Null padding.", v, s);
                            write_padding(is);
                        } 
                        else if (s != is) {
                            DBG("Short Read %zu instead of %lu.  Null padding.", s, (unsigned long) is);
                            write_padding(is - s);
                        }

                        // TODO: check if we need to add msleep() here
                    }
               }
               
                // TODO: IMPLEMENT copy to local variable before sending and double check locking - we dont want the page to change while we sent the current one - solve this issue
                //hyp_spin_lock(&pool->lock);       

                bitfield_index = phy_addr_to_bitfield_page_index(i); // TODO bug check
                if(bitfield_index < 0)
                    printk(KERN_EMERG "bitfield_index < 0 ; phy_addr = %lu\n", i);
                
                if(!IS_PAGE_SENT(pool->page_processed, bitfield_index))
                {
                    int itr_i, itr_j;

                    /* write original address */
                    write_vaddr((void*) &(i), sizeof(i));

                    /* copy page content to local buffer */
                    memcpy(page_buffer.memory, v, is);

                    /* check if the page changed while memcpy was executing */ //then send it from the local buffer 
                    for (itr_i = 0; itr_i < NUM_POOLS; itr_i++)
                    {
                        for (itr_j = 0; itr_j < POOL_SIZE; ++itr_j)
                            if(pool->pools[itr_i][itr_j].phy_addr == i) // if the pool contains a slot with address of i
                                break; 
                        
                        if(itr_j < POOL_SIZE)
                            break;
                    }  

                    /* if we exited the loop because of a break */
                    if(itr_i < NUM_POOLS && itr_j < POOL_SIZE)
                    {
                        /* send contents from the pool */
                        s = write_vaddr((void*)pool->pools[itr_i][itr_j].hyp_vaddr, is);
                    }
                    else
                        /* send contents from the local buffer */
                        s = write_vaddr(page_buffer.memory, is);

                    /* sent page to sent */                    
                    SET_PAGE_TO_SENT(pool->page_processed, bitfield_index);
                }
                //hyp_spin_unlock(&pool->lock);
            }

            kunmap(p);            

            if (s < 0) {
                DBG("Error writing page: vaddr %p ret: %zd.  Null padding.", v, s);
                write_padding(is);
            } else if (s != is) {
                DBG("Short Read %zu instead of %lu.  Null padding.", s, (unsigned long) is);
                write_padding(is - s);
            }
        }

#ifdef LIME_SUPPORTS_TIMING
        end = ktime_get_real();

        if (timeout > 0 && ktime_to_ms(ktime_sub(end, start)) > timeout) {
            DBG("Reading is too slow.  Skipping Range...");
            write_padding(res->end - i + 1 - is);
            break;
        }
#endif

    }
}

ssize_t write_vaddr(void * v, size_t is) {
    if(compute_digest == LIME_DIGEST_COMPUTE)
        compute_digest = ldigest_update(v, is);

    return RETRY_IF_INTURRUPTED(
        (method == LIME_METHOD_TCP) ? write_vaddr_tcp(v, is) : write_vaddr_disk(v, is)
    );
}

int setup(void) {
    return (method == LIME_METHOD_TCP) ? setup_tcp() : setup_disk();
}

void cleanup(void) {
    return (method == LIME_METHOD_TCP) ? cleanup_tcp() : cleanup_disk();
}

void cleanup_module(void) {

}

MODULE_LICENSE("GPL");
