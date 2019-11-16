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
static char * zero_page;

char * path = 0;
int dio = 0;
int port = 0;
int localhostonly = 0;

char * digest = 0;
int compute_digest = 0;

// microvisor stuff
struct LimePagePool* pool =  NULL;

extern struct resource iomem_resource;

module_param(path, charp, S_IRUGO);
module_param(dio, int, S_IRUGO);
module_param(format, charp, S_IRUGO);
module_param(localhostonly, int, S_IRUGO);
module_param(digest, charp, S_IRUGO);

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
    memset(page_processed, 0x00, PAGE_PROCESSED_SIZE); // zero out the page processed bit field
    
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

        /* Disable preemption */ // TODO: bug check this
        //int cpu = get_cpu();
	printk("Erez Lime\n");
        
        /* Transmiting the RAM range */
        write_range(p);

        /* Enable preemption */
        // put_cpu();

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
        
        msleep(10); // cpu performance of LiME is at 1% - rather than the usual 52%

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
                //hyp_spin_lock(&pool->lock);       

                //printk(KERN_EMERG "Cleaning pool of size %d\n", pool->size);
                
                // Clean unneccessary pages from the pool TODO: Make the microvisor not put unneccessary pages in the pool
                while(pool->size != 0)// && pool_peek_min(pool)->phy_addr < (resource_size_t) i)
                {

                    //pool_pop_min(pool);
                    //
                    // If current pool object 
                    //SET_PAGE_TO_SENT(page_processed, )//lime_current_page_index)
                }
                //printk(KERN_EMERG "Comparing pool->phy_addr = %p WITH i = %p\n", (void*) pool_peek_min(pool)->phy_addr, (void*)i);
                
                // Check if the microvisor has this page already -> if it has it then surely the page is outdated (*v is newer than pool->minimum)
                if(pool_peek_min(pool)->phy_addr == (resource_size_t) i)
                {
                    struct LimePageContext* min = pool_peek_min(pool);
                    
                    //printk(KERN_EMERG "writing page FROM pool, phy_addr = %p\n", (void*) min->phy_addr);

                    s = write_vaddr((void*) min->hyp_vaddr, is); // might not work
                    pool_pop_min(pool);
                }
                else
                    s = write_vaddr(v, is);

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
        
            lime_current_page_index++;
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
