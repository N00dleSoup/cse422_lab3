#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/mm.h>

#include <paging.h>

typedef struct {
    unsigned int nr_pages;
    unsigned int * page_indices;
    atomic_t refcnt;
} vma_tracker_t;

static atomic_t pages_created = ATOMIC_INIT(0);
static atomic_t pages_freed = ATOMIC_INIT(0);

static unsigned int demand_paging = 1;
module_param(demand_paging, uint, 0644);


static void
paging_vma_open(struct vm_area_struct * vma)
{
	vma_tracker_t * tracker = (vma_tracker_t *)vma->vm_private_data;
	//Increment the reference count
	atomic_inc( &tracker->refcnt );
    printk(KERN_INFO "paging_vma_open invoked\n");
}

static void
paging_vma_close(struct vm_area_struct * vma)
{
	int refs, i;
	struct page * page;
	vma_tracker_t * tracker =  vma->vm_private_data;
    printk(KERN_INFO "paging_vma_close invoked\n");
	refs = atomic_dec_return( &tracker->refcnt );
	if( refs == 0 ) {
		//Free the physical pages we allocated
		for(i = 0; i < tracker->nr_pages; ++i) {
			if(tracker->page_indices[i] != 0) {
				page = pfn_to_page(tracker->page_indices[i]);
				__free_pages(page, 0);
				atomic_inc(&pages_freed);
			}
		}
		//Free our data structures
		kfree( tracker->page_indices );
		kfree( tracker );
	}
}

static int
paging_vma_fault(struct vm_area_struct * vma,
                 struct vm_fault       * vmf)
{
	//Question: remap_pfn_range returns int, page_indices array is unsigned ints???
	unsigned long fault_page, p_offset;
	struct page * new_page;
    int remap;
	unsigned int phys_pfn;
	vma_tracker_t * tracker;

	printk(KERN_DEBUG "Page fault: in segment [0x%lx, 0x%lx), at VA 0x%lx\n",
        	vma->vm_start, vma->vm_end, (unsigned long)vmf->virtual_address );

	fault_page = PAGE_ALIGN( (unsigned long)vmf->virtual_address);
	p_offset = (fault_page - vma->vm_start) / PAGE_SIZE;
	
	//get 2^0 = 1 new pages
	new_page = alloc_pages( GFP_KERNEL, 0);
	if( !new_page ) {
		printk(KERN_ERR "Failed to allocate new page\n");
		return VM_FAULT_OOM;
	}
	//Remap the virtual address of the beginning of the faulting page to new phys page
	phys_pfn = page_to_pfn(new_page);
	remap = remap_pfn_range(vma, fault_page, phys_pfn, PAGE_SIZE, vma->vm_page_prot);
	if (remap != 0) {
		printk(KERN_ERR "Remapping pages failed!\n");
		return VM_FAULT_SIGBUS;
	}
	//Increase the count of allocated pages
	atomic_inc(&pages_created);	

	tracker = (vma_tracker_t *)vma->vm_private_data;
	tracker->page_indices[p_offset] = phys_pfn;

    return VM_FAULT_NOPAGE;
}

static struct vm_operations_struct
paging_vma_ops = 
{
    .open = paging_vma_open,
    .close = paging_vma_close,
    .fault = paging_vma_fault,
};


static unsigned int get_order(unsigned int val) {
	unsigned int shifts = 0;
	if(!value) {
		return 0;
	}
	if ( !(value & (value - 1)) ){
		--value;
	}
	while (value > 0) {
		value >>= 1;
		++shifts;
	}
	return shifts;
}

/* vma is the new virtual address segment for the process */
static int
paging_mmap(struct file           * filp,
            struct vm_area_struct * vma)
{
	vma_tracker_t * tracker;
    int i;
	/* prevent Linux from mucking with our VMA (expanding it, merging it 
     * with other VMAs, etc.
     */
    vma->vm_flags |= VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_NORESERVE | VM_DONTDUMP | VM_PFNMAP;
                      
    /* setup the vma->vm_ops, so we can catch page faults on this vma */
    vma->vm_ops = &paging_vma_ops;


	tracker = (vma_tracker_t *) kmalloc( sizeof(vma_tracker_t), GFP_KERNEL );
	if( !tracker ) {
		printk(KERN_ERR "Failed to malloc vm_private_data\n");
				return -ENOMEM;
	}
	
	tracker->nr_pages = (vma->vm_end - vma->vm_start) / PAGE_SIZE;
	printk(KERN_DEBUG "nr_pages = %u\n", tracker->nr_pages);

	//Create an array to hold PFN's and initialize them all to 0
	tracker->page_indices = (unsigned int *) kmalloc(tracker->nr_pages * 
			sizeof(unsigned int), GFP_KERNEL);
	if( !tracker->page_indices ) {
		printk(KERN_ERR "Failed to malloc page_indices\n");
		return -ENOMEM
	}
	for(i = 0; i < tracker->nr_pages; ++i) {
		tracker->page_indices[i] = 0;
	}

	atomic_set(&tracker->refcnt, 1);
	
	vma->vm_private_data = tracker;

    return 0;
}

static struct file_operations
dev_ops =
{
    .mmap = paging_mmap,
};

static struct miscdevice
dev_handle =
{
    .minor = MISC_DYNAMIC_MINOR,
    .name = PAGING_MODULE_NAME,
    .fops = &dev_ops,
};

/*** Kernel module initialization and teardown ***/
static int
paging_init(void)
{
    int status;

    /* Create a character device to communicate with user-space via file I/O operations */
    status = misc_register(&dev_handle);
    if (status != 0)
    {
        printk(KERN_ERR "Failed to register misc. device for module\n");
        return status;
    }

    printk(KERN_INFO "Loaded paging module\n");

    return 0;
}

static void
paging_exit(void)
{
    /* Deregister our device file */
    misc_deregister(&dev_handle);
	//Check if we created and freed the same number of pages
	printk(KERN_DEBUG "We allocated %d pages and freed %d pages\n", 
			atomic_read(&pages_created), atomic_read(&pages_freed));
	
	if( atomic_read(&pages_created) != atomic_read(&pages_freed) ) { 
		printk(KERN_ERR "Bad memory management!\n");
	}
    printk(KERN_INFO "Unloaded paging module\n");
}

module_init(paging_init);
module_exit(paging_exit);

/* Misc module info */
MODULE_LICENSE("GPL");
