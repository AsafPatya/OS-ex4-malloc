
#include <unistd.h>
#include <cstring>
#include <stdlib.h>
#include <sys/mman.h>


#define MAX_BLOCK_SIZE (100000000)
#define MMAP_MIN_SIZE (131072)
#define LARGE_KB (128)
#define KB (1024)

typedef struct MallocMetadata
{
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;

    /// now we need double linked list
    MallocMetadata *next_in_bin;
    MallocMetadata *prev_in_bin;
} MallocMetadata;

MallocMetadata *head = nullptr;
MallocMetadata *tail = nullptr;
MallocMetadata *bins_hist[LARGE_KB] = {nullptr};

static size_t meta_data_size = sizeof(MallocMetadata);
static size_t number_of_free_block = 0;
static size_t number_of_free_bytes = 0;
static size_t number_of_allocated_blocks = 0;
static size_t number_of_allocated_bytes = 0;
static size_t number_of_metadata_bytes = 0;

void *smalloc(size_t size);
void *scalloc(size_t num, size_t size);
void sfree(void *p);
void *srealloc(void *oldp, size_t size);

static void add_block_to_bin_hist(MallocMetadata *meta_pointer);
static void remove_block_from_bin_hist(MallocMetadata *meta_pointer);
static MallocMetadata *search_block_in_bin_hist_and_remove(size_t size);
static void split_block_by_size(MallocMetadata *meta_ptr, size_t size);
static void *allocation_mmap_by_size(size_t size);
static void deallocation_mmap_by_meta_ptr(MallocMetadata *meta_ptr);
static void* if_there_free_space(size_t size, MallocMetadata *new_free_block);
static void* try_wild(size_t size);
static void* mmap_reallocation(size_t size,void* oldp,MallocMetadata*old_meta_ptr);
static void* reg_reallocation(size_t size, MallocMetadata* old_meta_ptr,void*oldp);
////////////////////////////


inline MallocMetadata* meta_address_from_block(void* block_ptr){
    return (MallocMetadata*) ((char*)(block_ptr) - meta_data_size);
}

inline void* block_address_from_meta(MallocMetadata* meta_ptr){
    return (void*) ((char*)(meta_ptr) + meta_data_size);
}

static void add_block_to_bin_hist(MallocMetadata *meta_pointer)
{
    /// done
    int bin_hist_index_of_given_block = (meta_pointer->size) / KB;
    MallocMetadata *iter_bin_hist = bins_hist[bin_hist_index_of_given_block];

    /// case the d_linked list is empty, meta_ptr will be the first
    if (iter_bin_hist == nullptr)
    {
        bins_hist[bin_hist_index_of_given_block] = meta_pointer;
        return;
    }

    /// if the d_linked list not empty, than need to inset the meta_ptr in the right place.
    /// d_linked list suppose to be sorted by size
    /// first case: iter_bin_hist->size >= meta_ptr->size , so we put meta_ptr first and finish
    if (iter_bin_hist->size >= meta_pointer->size)
    {
        meta_pointer->next_in_bin = iter_bin_hist;
        iter_bin_hist->prev_in_bin = meta_pointer;
        bins_hist[bin_hist_index_of_given_block] = meta_pointer;
        return;
    }

    /// second case: iter_bin_hist->size < meta_ptr->size , so we need to search for the first meta that
    /// his size less than ptr_meta
    while (iter_bin_hist->next_in_bin != nullptr &&
           iter_bin_hist->next_in_bin->size < meta_pointer->size)
    {
        iter_bin_hist = iter_bin_hist->next_in_bin;
    }

    if (iter_bin_hist->next_in_bin != nullptr)
    {
        iter_bin_hist->next_in_bin->prev_in_bin = meta_pointer;
    }

    meta_pointer->next_in_bin = iter_bin_hist->next_in_bin;
    iter_bin_hist->next_in_bin = meta_pointer;
    meta_pointer->prev_in_bin = iter_bin_hist;
}

static void remove_block_from_bin_hist(MallocMetadata *meta_pointer)
{
    /// done
    int bin_hist_index_of_given_block = (meta_pointer->size) / KB;

    /// case the first meta is meta_pointer
    if (bins_hist[bin_hist_index_of_given_block] == meta_pointer)
    {
        if (meta_pointer->next_in_bin == nullptr)
        {
            /// case the d_linked_list consists only the meta_pointer
            bins_hist[bin_hist_index_of_given_block] = nullptr;
            return;
        }
        /// there are other meta in this d_linked list
        bins_hist[bin_hist_index_of_given_block] = meta_pointer->next_in_bin;
        meta_pointer->next_in_bin->prev_in_bin = nullptr;
        return;
    }

    /// case the first meta is not the meta_pointer
    if (meta_pointer->next_in_bin != nullptr)
    {
        meta_pointer->next_in_bin->prev_in_bin = meta_pointer->prev_in_bin;
    }
    /// dont know how this case is possible
    /// guess its just a check
    if (meta_pointer->next_in_bin == nullptr && meta_pointer->prev_in_bin == nullptr)
    {
        return;
    }

    meta_pointer->prev_in_bin->next_in_bin = meta_pointer->next_in_bin;

    /// reset the pinter of meta_pointer
    meta_pointer->next_in_bin = nullptr;
    meta_pointer->prev_in_bin = nullptr;
}

static MallocMetadata* search_block_in_bin_hist_and_remove(size_t size)
{
    /// done
    /// dont understand the function
    /// i think its search for the first block that size <= block.size, and just remove it.
    /// function change names done
    MallocMetadata *meta_iterator = nullptr;
    int index_in_bin_hist = size / KB;
    for (;index_in_bin_hist < LARGE_KB; index_in_bin_hist++)
    {
        if (bins_hist[index_in_bin_hist] != nullptr)
        {
            meta_iterator = bins_hist[index_in_bin_hist];
            while (meta_iterator != nullptr)
            {
                if (size<=meta_iterator->size)
                {
                    remove_block_from_bin_hist(meta_iterator);
                    return meta_iterator;
                }
                meta_iterator = meta_iterator->next_in_bin;
            }
        }
    }
    return nullptr;
}

static void split_block_by_size(MallocMetadata *meta_ptr, size_t size)
{
    /// done
    /// taking meta_ptr and add another block with the given size just after meta_ptr
    /// split meta_ptr to 2 blocks such that meta_ptr will be with size: size
    /// the new block will be with the res.

    /// give new_block the new address
    MallocMetadata *new_block = (MallocMetadata*)((char*)meta_ptr + meta_data_size + size);

    /// set parameters for new block
    new_block->is_free = true;
    new_block->next = meta_ptr->next;
    new_block->prev = meta_ptr;


    if (meta_ptr->next != nullptr)
    {
        meta_ptr->next->prev = new_block;
    }
    else
    {
        tail = new_block;
    }
    meta_ptr->next = new_block;
    new_block->size = meta_ptr->size - (meta_data_size + size);
    new_block->next_in_bin = nullptr;
    new_block->prev_in_bin = nullptr;

    /// set parameters for meta_ptr

    meta_ptr->size = size;
    meta_ptr->is_free = false;

    /// add new block to hist
    add_block_to_bin_hist(new_block);
}

static void *allocation_mmap_by_size(size_t size)
{
    /// done
    void *new_address = mmap(NULL,
                             (size + meta_data_size),
                             PROT_WRITE | PROT_READ,
                             MAP_ANONYMOUS | MAP_PRIVATE,
                             -1,
                             0);
    if (new_address == (void *)(-1))
    {
        return nullptr;
    }
    MallocMetadata *new_meta_data = (MallocMetadata*)new_address;
    new_meta_data->is_free = false;
    new_meta_data->size = size;
    new_meta_data->next = nullptr;
    new_meta_data->prev = nullptr;
    new_meta_data->next_in_bin = nullptr;
    new_meta_data->prev_in_bin = nullptr;

    /// set counters
    number_of_metadata_bytes = number_of_metadata_bytes + meta_data_size;
    number_of_allocated_blocks = number_of_allocated_blocks +1;
    number_of_allocated_bytes = number_of_allocated_bytes + size;

    return block_address_from_meta(new_meta_data);
}


static void deallocation_mmap_by_meta_ptr(MallocMetadata *meta_ptr)
{
    /// done
    number_of_allocated_blocks = number_of_allocated_blocks - 1;
    number_of_allocated_bytes = number_of_allocated_bytes - meta_ptr->size;
    number_of_metadata_bytes = number_of_metadata_bytes - meta_data_size;

    munmap(meta_ptr, meta_ptr->size + meta_data_size);
    return;
}
static void* if_there_free_space(size_t size, MallocMetadata *new_free_block)
{
    /// done
    /// dont understand what the function does
    new_free_block->is_free = false;
    unsigned long u_l_size = (unsigned long)size;
    unsigned long u_l_meta_data_size = (unsigned long)meta_data_size;
    unsigned long u_l_nfree_block = (unsigned long)new_free_block->size;

    bool ans1 = (u_l_nfree_block >= u_l_size + u_l_meta_data_size);
    bool ans2 = (new_free_block->size - size - meta_data_size >= LARGE_KB);
    bool condition = ans1 && ans2;
    if (condition)
    {
        split_block_by_size(new_free_block, size);
        number_of_free_bytes = number_of_free_bytes -  (size + meta_data_size) ;
        number_of_allocated_blocks += 1;
        number_of_allocated_bytes = number_of_allocated_bytes - meta_data_size;
        number_of_metadata_bytes =number_of_metadata_bytes + meta_data_size;
    }
    else
    {
        number_of_free_block -= 1;
        number_of_free_bytes = number_of_free_bytes - new_free_block->size;
    }
    return block_address_from_meta(new_free_block);
}

static void* try_wild(size_t size)
{
    /// done
    /// dont understand what the function does
    size_t tail_size = tail->size;
    size_t size_to_add = size - tail_size;
    void* new_address = sbrk((intptr_t)size_to_add);
    if (*((int *)new_address) == -1)
    {
        return nullptr;
    }

    number_of_free_block -= 1;
    number_of_free_bytes = number_of_free_bytes - tail_size;
    number_of_allocated_bytes =number_of_allocated_bytes + size_to_add;

    remove_block_from_bin_hist(tail);
    tail->size = tail->size + size_to_add;
    tail->is_free = false;
    return block_address_from_meta(tail);
}
static void* mmap_reallocation(size_t size, void* oldp,MallocMetadata*old_meta_ptr)
{
    /// done
    /// dont understand what the function does
    void *new_address = smalloc(size);
    if (new_address == nullptr)
    {
        return nullptr;
    }

//    size_t size_to_move = (old_meta_ptr->size < size)?old_meta_ptr->size:size;
    size_t size_to_move = 0;
    if (old_meta_ptr->size < size)
    {
        size_to_move = old_meta_ptr->size;
    }
    else
    {
        size_to_move = size;
    }

    memmove(new_address, oldp, size_to_move);
    sfree(oldp);
    return new_address;
}
static void* reg_reallocation(size_t size, MallocMetadata* old_meta_ptr,void* oldp)
{
    unsigned long u_l_size = (unsigned long)size;
    unsigned long u_l_meta_data_size = (unsigned long)meta_data_size;
    unsigned long u_l_old_meta_ptr = (unsigned long)old_meta_ptr->size;
    bool ans1 = (u_l_old_meta_ptr >= u_l_size + u_l_meta_data_size);
    int size_to_add = old_meta_ptr->size - size - meta_data_size;
    bool ans2=(size_to_add >= LARGE_KB);
    bool condition = ans1 && ans2;
    if (condition)
    {
        split_block_by_size(old_meta_ptr, size);
        number_of_free_block += 1;
        number_of_free_bytes = number_of_free_bytes + size_to_add;
        number_of_allocated_blocks += 1;
        number_of_allocated_bytes = number_of_allocated_bytes -  meta_data_size;
        number_of_metadata_bytes = number_of_metadata_bytes + meta_data_size;
    }
    return oldp;
}

/// #smalloc
void *smalloc(size_t size)
{
    /// done
    if (size == 0 || size > MAX_BLOCK_SIZE)
    {
        return nullptr;
    }

    //mmap case
    if (size >= MMAP_MIN_SIZE)
    {
        void *new_address = allocation_mmap_by_size(size);
        return new_address;
    }

    //any free space
    MallocMetadata *new_free_block = search_block_in_bin_hist_and_remove(size);
    if (new_free_block != nullptr)
    {
        return if_there_free_space(size,new_free_block);
    }
//    bool tail_is_free = tail->is_free;
    if (tail != nullptr && tail->is_free)
    {
        return try_wild(size);
    }

    //reg case
    void* new_address = sbrk((intptr_t)(size + meta_data_size));
    if (*((int *)new_address) == -1)
    {
        return nullptr;
    }

    MallocMetadata *new_meta_data = (MallocMetadata*)new_address;
    new_meta_data->is_free = false;
    new_meta_data->next = nullptr;
    new_meta_data->size = size;
    new_meta_data->next_in_bin = nullptr;
    new_meta_data->prev_in_bin = nullptr;

    if (head == nullptr)
    {
        head = new_meta_data;
        new_meta_data->prev = nullptr;
    }
    else
    {
        new_meta_data->prev = tail;
        if (tail != nullptr)
        {
            tail->next = new_meta_data;
        }
    }
    tail = new_meta_data;
    number_of_allocated_blocks += 1;
    number_of_allocated_bytes = number_of_allocated_bytes + size;
    number_of_metadata_bytes = number_of_metadata_bytes + meta_data_size;
    return block_address_from_meta(new_meta_data);
}

/// #scalloc
void *scalloc(size_t num, size_t size)
{
    /// done
    size_t new_size = num * size;
    void *new_address = smalloc(new_size);
    if (new_address == nullptr)
    {
        return nullptr;
    }
    memset(new_address, 0, new_size);
    return new_address;
}

/// #sfree
void sfree(void *p)
{
    /// done
    if (p == nullptr)
        return;

    MallocMetadata *meta_pointer = meta_address_from_block(p);
    if (meta_pointer->is_free)
    {
        return;
    }
    bool cond1 = meta_pointer->size >= MMAP_MIN_SIZE;
    if (cond1)
    {
        deallocation_mmap_by_meta_ptr(meta_pointer);
        return;
    }
    number_of_free_bytes =number_of_free_bytes + meta_pointer->size;
    meta_pointer->is_free = true;
    number_of_free_block += 1;

//    bool cond2 = meta_pointer->next->is_free;
    // try next
    if (meta_pointer->next != nullptr && meta_pointer->next->is_free)
    {
        remove_block_from_bin_hist(meta_pointer->next);
        size_t meta_pointer_size = meta_pointer->size;
        meta_pointer->size = meta_pointer_size + meta_pointer->next->size + meta_data_size;
        meta_pointer->next = meta_pointer->next->next;
        if (meta_pointer->next != nullptr)
        {
            meta_pointer->next->prev = meta_pointer;
        }
        else
        {
            tail = meta_pointer;
        }

        number_of_free_block -= 1;
        number_of_free_bytes = number_of_free_bytes + meta_data_size;
        number_of_allocated_blocks -= 1;
        number_of_allocated_bytes = number_of_allocated_bytes + meta_data_size;
        number_of_metadata_bytes = number_of_metadata_bytes - meta_data_size;
    }

    // try prev
//    bool cond3 = meta_pointer->prev->is_free;
    if (meta_pointer->prev != nullptr && meta_pointer->prev->is_free)
    {
        remove_block_from_bin_hist(meta_pointer->prev);
        meta_pointer = meta_pointer->prev;
        size_t meta_pointer_size = meta_pointer->size;
        meta_pointer->size = meta_pointer_size + meta_pointer->next->size + meta_data_size;

        meta_pointer->next = meta_pointer->next->next;
        if (meta_pointer->next != nullptr)
        {
            meta_pointer->next->prev = meta_pointer;
        }
        else
        {
            tail = meta_pointer;
        }

        number_of_free_block -= 1;
        number_of_free_bytes = number_of_free_bytes + meta_data_size;
        number_of_allocated_blocks -= 1;
        number_of_allocated_bytes = number_of_allocated_bytes + meta_data_size;
        number_of_metadata_bytes = number_of_metadata_bytes - meta_data_size;
    }

    add_block_to_bin_hist(meta_pointer);
}

/// #srealloc
void *srealloc(void *oldp, size_t size)
{
    ///
    if (size == 0 || size > MAX_BLOCK_SIZE)
    {
        return nullptr;
    }
    if (oldp == nullptr)
    {
        return (smalloc(size));
    }
    MallocMetadata *old_meta_pointer = meta_address_from_block(oldp);

    //mmap realloc
    bool cond1 = (size >= MMAP_MIN_SIZE);
    if (cond1)
    {
        return mmap_reallocation(size,oldp,old_meta_pointer);
    }


    // reg
    bool cond2 = (size<=old_meta_pointer->size);
    if (cond2)
    {
        return reg_reallocation(size,old_meta_pointer,oldp);
    }

    // try join prev
    MallocMetadata *old_p_prev_block = old_meta_pointer->prev;
    bool cond3 = (old_p_prev_block->is_free);
    if (old_p_prev_block != nullptr && cond3)
    {
        size_t old_meta_pointer_prev_size = old_meta_pointer->prev->size;
        size_t slot_with_prev = old_meta_pointer_prev_size + meta_data_size + old_meta_pointer->size;
        bool cond4 = (slot_with_prev >= size);
        if (cond4)
        {
            remove_block_from_bin_hist(old_p_prev_block);

            number_of_free_block-=1;
            number_of_free_bytes =number_of_free_bytes- old_p_prev_block->size;
            number_of_allocated_blocks-=1;
            number_of_allocated_bytes =number_of_allocated_bytes+ meta_data_size;
            number_of_metadata_bytes =number_of_metadata_bytes- meta_data_size;

            old_p_prev_block->size = slot_with_prev;
            old_p_prev_block->is_free = false;

            old_p_prev_block->next = old_meta_pointer->next;
            bool cond5 = (old_meta_pointer->next != nullptr);
            if (cond5)
            {
                old_meta_pointer->next->prev = old_p_prev_block;
            }
            else
            {
                tail = old_p_prev_block;
            }

            void *destination = block_address_from_meta(old_p_prev_block);
            memmove(destination, oldp, old_meta_pointer->size);

            unsigned long u_l_size = (unsigned long)size;
            unsigned long u_l_meta_data_size = (unsigned long)meta_data_size;
            unsigned long u_l_old_p_prev_block_size = (unsigned long)old_p_prev_block->size ;
            bool ans1 = ((unsigned long)old_p_prev_block->size >= u_l_size+u_l_meta_data_size);
            bool ans2= (u_l_old_p_prev_block_size - size - meta_data_size >= LARGE_KB);
            bool cond6 = ans1 && ans2;
            if (cond6)
            {
                split_block_by_size(old_p_prev_block, size);

                number_of_free_block+=1;
                number_of_free_bytes =number_of_free_bytes+ old_p_prev_block->next->size;
                number_of_allocated_blocks+=1;
                number_of_allocated_bytes =number_of_allocated_bytes- meta_data_size;
                number_of_metadata_bytes =number_of_metadata_bytes+ meta_data_size;
            }
            return block_address_from_meta(old_p_prev_block);
        }
    }

    // try join next
    MallocMetadata *next_block_pointer = old_meta_pointer->next;
//    bool cond7 = next_block_pointer != nullptr && next_block_pointer->is_free;
    if (next_block_pointer != nullptr && next_block_pointer->is_free)
    {
        unsigned long u_l_old_p_next_block_size = (unsigned long)old_meta_pointer->next->size;
        size_t slot_with_next = u_l_old_p_next_block_size + meta_data_size + old_meta_pointer->size;
        bool cond8 = slot_with_next >= size;
        if (cond8)
        {
            remove_block_from_bin_hist(next_block_pointer);

            number_of_free_block-1;
            number_of_free_bytes =number_of_free_bytes -  next_block_pointer->size;
            number_of_allocated_blocks-=1;
            number_of_allocated_bytes =number_of_allocated_bytes+ meta_data_size;
            number_of_metadata_bytes =number_of_metadata_bytes- meta_data_size;

            old_meta_pointer->size = slot_with_next;

            old_meta_pointer->next = next_block_pointer->next;
            bool cond9 = (next_block_pointer->next != nullptr);
            if (cond9)
            {
                next_block_pointer->next->prev = old_meta_pointer;
            }
            else
            {
                tail = old_meta_pointer;
            }
            unsigned long u_l_size = (unsigned long)size;
            unsigned long u_l_meta_data_size = (unsigned long)meta_data_size;
            unsigned long u_l_old_meta_pointer_size = (unsigned long)old_meta_pointer->size;
            bool ans1 = ((unsigned long)old_meta_pointer->size >= u_l_size+u_l_meta_data_size);
            bool ans2=(u_l_old_meta_pointer_size - size - meta_data_size>= LARGE_KB);
            bool cond10 = ans1&&ans2;
            if (cond10)
            {
                split_block_by_size(old_meta_pointer, size);

                number_of_free_block += 1;
                number_of_free_bytes =number_of_free_bytes + old_meta_pointer->next->size;
                number_of_allocated_blocks += 1;
                number_of_allocated_bytes =number_of_allocated_bytes - meta_data_size;
                number_of_metadata_bytes =number_of_metadata_bytes+ meta_data_size;
            }
            return oldp;
        }
    }

    // prev try
//    bool cond11 = old_p_prev_block != nullptr && old_p_prev_block->is_free &&
//                  next_block_pointer != nullptr  && next_block_pointer->is_free;
    if (old_p_prev_block != nullptr && old_p_prev_block->is_free &&
        next_block_pointer != nullptr  && next_block_pointer->is_free)
    {
        unsigned long u_l_old_meta_pointer_next_size = (unsigned long)old_meta_pointer->next->size;
        unsigned long u_l_old_meta_pointer_prev_size = (unsigned long)old_meta_pointer->prev->size;
        size_t next_and_prev_block = u_l_old_meta_pointer_prev_size +
                                     u_l_old_meta_pointer_next_size +
                                     2 * meta_data_size + old_meta_pointer->size;
        bool cond12 = size<=next_and_prev_block;
        if (cond12)
        {
            remove_block_from_bin_hist(old_p_prev_block);
            remove_block_from_bin_hist(next_block_pointer);



            number_of_free_block =number_of_free_block - 2;

            size_t next_block_pointer_size = next_block_pointer->size;
            size_t prev_block_pointer_size = old_p_prev_block->size;
            number_of_free_bytes = number_of_free_bytes - next_block_pointer_size - prev_block_pointer_size;

            number_of_allocated_blocks =number_of_allocated_blocks- 2;
            number_of_allocated_bytes =number_of_allocated_bytes+ 2 * meta_data_size;
            number_of_metadata_bytes =number_of_metadata_bytes- 2 * meta_data_size;

            old_p_prev_block->size = next_and_prev_block;
            old_p_prev_block->is_free = false;

            old_p_prev_block->next = next_block_pointer->next;
            bool cond13 = old_p_prev_block->next != nullptr;
            if (cond13)
            {
                old_p_prev_block->next->prev = old_p_prev_block;
            }
            else
            {
                tail = old_p_prev_block;
            }


            void *destination = block_address_from_meta(old_p_prev_block);
            memmove(destination, oldp, old_meta_pointer->size);

            unsigned long u_l_size = (unsigned long)size;
            unsigned long u_l_meta_data_size = (unsigned long)meta_data_size;
            unsigned long u_l_old_p_prev_block_size = (unsigned long)old_p_prev_block->size;
            bool ans1 = (u_l_old_p_prev_block_size >= u_l_size+ u_l_meta_data_size);
            bool ans2=(old_p_prev_block->size - size - meta_data_size >= LARGE_KB);
            bool cond14 = ans1&& ans2;
            if (cond14)
            {
                split_block_by_size(old_p_prev_block, size);

                number_of_free_block+=1;
                number_of_free_bytes =number_of_free_bytes+ old_p_prev_block->next->size;
                number_of_allocated_blocks+=1;
                number_of_allocated_bytes =number_of_allocated_bytes- meta_data_size;
                number_of_metadata_bytes =number_of_metadata_bytes+ meta_data_size;
            }
            return block_address_from_meta(old_p_prev_block);
        }
    }

    //wild case
    bool cond15 = tail == old_meta_pointer;
    if(cond15){
        tail->is_free = true;
    }
    size_t old_ptr_size = old_meta_pointer->size;
    void *destination = smalloc(size);
    if (destination == nullptr)
    {
        return nullptr;
    }
//    bool cond16 = destination == block_address_from_meta(tail)&&(tail == old_meta_pointer);
    if(destination == block_address_from_meta(tail)&&(tail == old_meta_pointer))
    {
        number_of_free_block+=1;
        number_of_free_bytes =number_of_free_bytes+ old_ptr_size;
        return oldp;
    }

    memmove(destination, oldp, old_meta_pointer->size);
    sfree(oldp);
    return destination;
}

size_t _num_free_blocks()
{
    return number_of_free_block;
}

size_t _num_free_bytes()
{
    return number_of_free_bytes;
}

size_t _num_allocated_blocks()
{
    return number_of_allocated_blocks;
}

size_t _num_allocated_bytes()
{
    return number_of_allocated_bytes;
}

size_t _num_meta_data_bytes()
{
    return number_of_metadata_bytes;
}

size_t _size_meta_data()
{
    return meta_data_size;
}
