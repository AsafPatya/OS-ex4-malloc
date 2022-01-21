
#include <unistd.h>
#include <cstring>
#include <stdlib.h>
#include <sys/mman.h>


#define MAX_BLOCK_SIZE (100000000)
#define MMAP_MIN_SIZE (131072)
#define LARGE_KB (128)
#define KB (1024)
#define ALIGNED_TO_8 (8)

typedef struct MallocMetadata
{
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
    MallocMetadata *next_in_bin;
    MallocMetadata *prev_in_bin;
} MallocMetadata;
///declere global

MallocMetadata *head = nullptr;
MallocMetadata *tail = nullptr;
MallocMetadata *bins[LARGE_KB] = {nullptr};

static size_t size_meta_data = sizeof(MallocMetadata);
static size_t num_free_blocks = 0;
static size_t num_free_bytes = 0;
static size_t num_allocated_blocks = 0;
static size_t num_allocated_bytes = 0;
static size_t num_metadata_bytes = 0;

void *smalloc(size_t size);
void *scalloc(size_t num, size_t size);
void sfree(void *p);
void *srealloc(void *oldp, size_t size);
static void add_block_to_bin(MallocMetadata *meta_ptr);
static void remove_block_from_bin(MallocMetadata *meta_ptr);
static MallocMetadata *search_block_in_bin_and_remove(size_t size);
static void split_block(MallocMetadata *meta_ptr, size_t size);
static void *alloc_mmap(size_t size);
static void dealloc_mmap(MallocMetadata *meta_ptr);
static void* if_free_space(size_t size, MallocMetadata *_nfree_block);
static void* trywild(size_t size);
static void* mmap_realloc(size_t size,void* oldp,MallocMetadata*old_meta_ptr);
static void* reg_realloc(size_t size, MallocMetadata* old_meta_ptr,void*oldp);
////////////////////////////
inline MallocMetadata* meta_addr_from_block(void* p){
    return (MallocMetadata*) ((char*)(p) - size_meta_data);
}

inline void* block_addr_from_meta(MallocMetadata* meta){
    return (void*) ((char*)(meta) + size_meta_data);
}

static void add_block_to_bin(MallocMetadata *meta_ptr){
    int bin_index_of_block = (meta_ptr->size) / KB;
    MallocMetadata *iter = bins[bin_index_of_block];
    if (iter == nullptr)
    {
        bins[bin_index_of_block] = meta_ptr;
        return;
    }

    if (iter->size >= meta_ptr->size)
    {
        meta_ptr->next_in_bin = iter;
        iter->prev_in_bin = meta_ptr;

        bins[bin_index_of_block] = meta_ptr;

        return;
    }

    while (iter->next_in_bin != nullptr && iter->next_in_bin->size < meta_ptr->size)
    {
        iter = iter->next_in_bin;
    }

    if (iter->next_in_bin != nullptr)
    {
        iter->next_in_bin->prev_in_bin = meta_ptr;
    }

    meta_ptr->next_in_bin = iter->next_in_bin;
    iter->next_in_bin = meta_ptr;
    meta_ptr->prev_in_bin = iter;
}

static void remove_block_from_bin(MallocMetadata *meta_ptr){
    int bin_index_of_block = (meta_ptr->size) / KB;
    if (bins[bin_index_of_block] == meta_ptr)
    {
        if (meta_ptr->next_in_bin == nullptr)
        {
            bins[bin_index_of_block] = nullptr;
            return;
        }
        bins[bin_index_of_block] = meta_ptr->next_in_bin;
        meta_ptr->next_in_bin->prev_in_bin = nullptr;

        return;
    }
    if (meta_ptr->next_in_bin != nullptr)
    {
        meta_ptr->next_in_bin->prev_in_bin = meta_ptr->prev_in_bin;
    }
    if(meta_ptr->next_in_bin == nullptr && meta_ptr->prev_in_bin == nullptr){
        return;
    }

    meta_ptr->prev_in_bin->next_in_bin = meta_ptr->next_in_bin;

    meta_ptr->next_in_bin = nullptr;
    meta_ptr->prev_in_bin = nullptr;
}

static MallocMetadata *search_block_in_bin_and_remove(size_t size){
    MallocMetadata *iterator = nullptr;
    for ( int i = size / KB;  i < LARGE_KB; i++)
    {
        if (bins[i] != nullptr)
        {
            iterator = bins[i];
            while (iterator != nullptr)
            {
                if (size<=iterator->size)
                {
                    remove_block_from_bin(iterator);
                    return iterator;
                }
                iterator = iterator->next_in_bin;
            }
        }
    }
    return nullptr;
}

static void split_block(MallocMetadata *meta_ptr, size_t size){
    MallocMetadata *_nblock = (MallocMetadata *)((char *)meta_ptr + size_meta_data + size);
    _nblock->is_free = true;
    _nblock->next = meta_ptr->next;
    _nblock->prev = meta_ptr;
    if (meta_ptr->next != nullptr)
    {
        meta_ptr->next->prev = _nblock;
    }
    else{
        tail = _nblock;
    }
    meta_ptr->next = _nblock;
    _nblock->size = meta_ptr->size - (size_meta_data + size);
    _nblock->next_in_bin = nullptr;
    _nblock->prev_in_bin = nullptr;

    meta_ptr->size = size;
    meta_ptr->is_free = false;

    add_block_to_bin(_nblock);
}

static void *alloc_mmap(size_t size){

    void *_naddr = mmap(NULL, (size + size_meta_data), PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (_naddr == (void *)(-1))
        return nullptr;

    MallocMetadata *_nmeta_data = (MallocMetadata *)_naddr;
    _nmeta_data->is_free = false;
    _nmeta_data->size = size;
    _nmeta_data->next = nullptr;
    _nmeta_data->prev = nullptr;
    _nmeta_data->next_in_bin = nullptr;
    _nmeta_data->prev_in_bin = nullptr;

    //set counters
    num_metadata_bytes += size_meta_data;
    num_allocated_blocks++;
    num_allocated_bytes += size;

    return block_addr_from_meta(_nmeta_data);
}


static void dealloc_mmap(MallocMetadata *meta_ptr){

    num_allocated_blocks--;
    num_allocated_bytes -= meta_ptr->size;
    num_metadata_bytes -= size_meta_data;

    munmap(meta_ptr, meta_ptr->size + size_meta_data);

    return;
}
static void* if_free_space(size_t size, MallocMetadata *_nfree_block){
    _nfree_block->is_free = false;
    bool ans1=((unsigned long)_nfree_block->size >= (unsigned long)size+(unsigned long)size_meta_data);
    bool ans2=(_nfree_block->size - size - size_meta_data >= LARGE_KB);

    if (ans1&&ans2)
    {
        split_block(_nfree_block, size);
        num_free_bytes -= (size + size_meta_data) ;
        num_allocated_blocks++;
        num_allocated_bytes -= size_meta_data;
        num_metadata_bytes += size_meta_data;
    }
    else
    {
        num_free_blocks--;
        num_free_bytes -= _nfree_block->size;
    }
    return block_addr_from_meta(_nfree_block);
}
static void* trywild(size_t size){
    size_t size_to_add = size - tail->size;
    void* _naddr = sbrk((intptr_t)size_to_add);
    if (*((int *)_naddr) == -1)
    {
        return nullptr;
    }

    num_free_blocks--;
    num_free_bytes -= tail->size;
    num_allocated_bytes += size_to_add;

    remove_block_from_bin(tail);
    tail->size += size_to_add;
    tail->is_free = false;

    return block_addr_from_meta(tail);
}
static void* mmap_realloc(size_t size,void* oldp,MallocMetadata*old_meta_ptr){
    void *_naddr = smalloc(size);
    if (_naddr == nullptr)
    {
        return nullptr;
    }
    size_t size_to_move = (old_meta_ptr->size < size)?old_meta_ptr->size:size;
    memmove(_naddr, oldp, size_to_move);
    sfree(oldp);
    return _naddr;
}
static void* reg_realloc(size_t size, MallocMetadata* old_meta_ptr,void*oldp){
    bool ans1 = ((unsigned long)old_meta_ptr->size >= (unsigned long)size+(unsigned long)size_meta_data);
    int size_to_add = old_meta_ptr->size - size - size_meta_data;
    bool ans2=(size_to_add >= LARGE_KB);
    if (ans1 && ans2)
    {
        split_block(old_meta_ptr, size);

        num_free_blocks++;
        num_free_bytes += size_to_add;
        num_allocated_blocks++;
        num_allocated_bytes -= size_meta_data;
        num_metadata_bytes += size_meta_data;
    }
    return oldp;
}

void *smalloc(size_t size)
{

    if (size == 0 || size > MAX_BLOCK_SIZE)
    {
        return nullptr;
    }
    if (size % ALIGNED_TO_8 != 0) {
        size += ALIGNED_TO_8- (size % ALIGNED_TO_8);
    }
    //mmap case
    if (size >= MMAP_MIN_SIZE)
    {
        void *_naddr=alloc_mmap(size);
        return _naddr;
    }

    //any free space
    MallocMetadata *_nfree_block = search_block_in_bin_and_remove(size);
    if (_nfree_block != nullptr)
    {
        return if_free_space(size,_nfree_block);
    }
    if (tail != nullptr && tail->is_free)
    {
        return trywild(size);
    }

    //reg case
    void* _naddr = sbrk((intptr_t)(size + size_meta_data));
    if (*((int *)_naddr) == -1)
        return nullptr;

    MallocMetadata *new_metaData = (MallocMetadata *)_naddr;
    new_metaData->is_free = false;
    new_metaData->next = nullptr;
    new_metaData->size = size;
    new_metaData->next_in_bin = nullptr;
    new_metaData->prev_in_bin = nullptr;

    if (head == nullptr)
    {
        head = new_metaData;
        new_metaData->prev = nullptr;
    }
    else
    {
        new_metaData->prev = tail;
        if (tail != nullptr)
        {
            tail->next = new_metaData;
        }
    }
    tail = new_metaData;

    num_allocated_blocks++;
    num_allocated_bytes += size;
    num_metadata_bytes += size_meta_data;
    return block_addr_from_meta(new_metaData);
}

void *scalloc(size_t num, size_t size)
{
    size_t _nsize=num * size;
    void *_naddr = smalloc(_nsize);
    if (_naddr == nullptr)
    {
        return nullptr;
    }
    memset(_naddr, 0, _nsize);
    return _naddr;
}

void sfree(void *p)
{
    if (p == nullptr)
        return;

    MallocMetadata *meta_ptr = meta_addr_from_block(p);
    if (meta_ptr->is_free)
    {
        return;
    }
    if (meta_ptr->size >= MMAP_MIN_SIZE)
    {
        dealloc_mmap(meta_ptr);
        return;
    }
    num_free_bytes += meta_ptr->size;
    meta_ptr->is_free = true;
    num_free_blocks++;

    // try next
    if (meta_ptr->next != nullptr && meta_ptr->next->is_free)
    {
        remove_block_from_bin(meta_ptr->next);
        meta_ptr->size = meta_ptr->size + meta_ptr->next->size + size_meta_data;
        meta_ptr->next = meta_ptr->next->next;
        if (meta_ptr->next != nullptr)
        {
            meta_ptr->next->prev = meta_ptr;
        }
        else
        {
            tail = meta_ptr;
        }

        num_free_blocks--;
        num_free_bytes += size_meta_data;
        num_allocated_blocks--;
        num_allocated_bytes += size_meta_data;
        num_metadata_bytes -= size_meta_data;
    }

    // try prev
    if (meta_ptr->prev != nullptr && meta_ptr->prev->is_free)
    {
        remove_block_from_bin(meta_ptr->prev);
        meta_ptr = meta_ptr->prev;
        meta_ptr->size = meta_ptr->size + meta_ptr->next->size + size_meta_data;

        meta_ptr->next = meta_ptr->next->next;
        if (meta_ptr->next != nullptr)
        {
            meta_ptr->next->prev = meta_ptr;
        }
        else
        {
            tail = meta_ptr;
        }

        num_free_blocks--;
        num_free_bytes += size_meta_data;
        num_allocated_blocks--;
        num_allocated_bytes += size_meta_data;
        num_metadata_bytes -= size_meta_data;
    }

    add_block_to_bin(meta_ptr);
}

void *srealloc(void *oldp, size_t size)
{
    if (size == 0 || size > MAX_BLOCK_SIZE)
    {
        return nullptr;
    }
    if (oldp == nullptr)
    {
        return (smalloc(size));
    }
    if (size % ALIGNED_TO_8 != 0) {
        size += ALIGNED_TO_8- (size % ALIGNED_TO_8);
    }
    MallocMetadata *old_meta_ptr = meta_addr_from_block(oldp);
    //mmap realloc
    if (size >= MMAP_MIN_SIZE)
    {
        return mmap_realloc(size,oldp,old_meta_ptr);
    }
    // reg
    if (size<=old_meta_ptr->size)
    {
        return reg_realloc(size,old_meta_ptr,oldp);
    }
    // try join prev
    MallocMetadata *prev_block = old_meta_ptr->prev;
    if (prev_block != nullptr && prev_block->is_free)
    {
        size_t slot_with_prev = old_meta_ptr->prev->size + size_meta_data + old_meta_ptr->size;
        if (slot_with_prev >= size)
        {
            remove_block_from_bin(prev_block);

            num_free_blocks--;
            num_free_bytes -= prev_block->size;
            num_allocated_blocks--;
            num_allocated_bytes += size_meta_data;
            num_metadata_bytes -= size_meta_data;

            prev_block->size = slot_with_prev;
            prev_block->is_free = false;

            prev_block->next = old_meta_ptr->next;
            if (old_meta_ptr->next != nullptr)
            {
                old_meta_ptr->next->prev = prev_block;
            }
            else
            {
                tail = prev_block;
            }

            void *dest = block_addr_from_meta(prev_block);
            memmove(dest, oldp, old_meta_ptr->size);

            bool ans1 = ((unsigned long)prev_block->size >= (unsigned long)size+(unsigned long)size_meta_data);
            bool ans2=(prev_block->size - size - size_meta_data >= LARGE_KB);
            if (ans1 && ans2)
            {
                split_block(prev_block, size);

                num_free_blocks++;
                num_free_bytes += prev_block->next->size;
                num_allocated_blocks++;
                num_allocated_bytes -= size_meta_data;
                num_metadata_bytes += size_meta_data;
            }
            return block_addr_from_meta(prev_block);
        }
    }

    // try join next
    MallocMetadata *next_block = old_meta_ptr->next;
    if (next_block != nullptr && next_block->is_free)
    {
        size_t slot_with_next = old_meta_ptr->next->size + size_meta_data + old_meta_ptr->size;
        if (slot_with_next >= size)
        {
            remove_block_from_bin(next_block);

            num_free_blocks--;
            num_free_bytes -= next_block->size;
            num_allocated_blocks--;
            num_allocated_bytes += size_meta_data;
            num_metadata_bytes -= size_meta_data;

            old_meta_ptr->size = slot_with_next;

            old_meta_ptr->next = next_block->next;
            if (next_block->next != nullptr)
            {
                next_block->next->prev = old_meta_ptr;
            }
            else
            {
                tail = old_meta_ptr;
            }

            bool ans1 = ((unsigned long)old_meta_ptr->size >= (unsigned long)size+(unsigned long)size_meta_data);
            bool ans2=(old_meta_ptr->size - size - size_meta_data>= LARGE_KB);
            if (ans1&&ans2)
            {
                split_block(old_meta_ptr, size);

                num_free_blocks++;
                num_free_bytes += old_meta_ptr->next->size;
                num_allocated_blocks++;
                num_allocated_bytes -= size_meta_data;
                num_metadata_bytes += size_meta_data;
            }
            return oldp;
        }
    }

    // prev try
    if (prev_block != nullptr && prev_block->is_free && next_block != nullptr  && next_block->is_free)
    {
        size_t next_and_prev_block = old_meta_ptr->prev->size + old_meta_ptr->next->size + 2 * size_meta_data + old_meta_ptr->size;
        if (size<=next_and_prev_block)
        {
            remove_block_from_bin(prev_block);
            remove_block_from_bin(next_block);

            num_free_blocks -= 2;
            num_free_bytes = num_free_bytes - next_block->size - prev_block->size;
            num_allocated_blocks -= 2;
            num_allocated_bytes += 2 * size_meta_data;
            num_metadata_bytes -= 2 * size_meta_data;

            prev_block->size = next_and_prev_block;
            prev_block->is_free = false;

            prev_block->next = next_block->next;
            if (prev_block->next != nullptr)
            {
                prev_block->next->prev = prev_block;
            }
            else
            {
                tail = prev_block;
            }


            void *dest = block_addr_from_meta(prev_block);
            memmove(dest, oldp, old_meta_ptr->size);

            bool ans1 = ((unsigned long)prev_block->size >= (unsigned long)size+(unsigned long)size_meta_data);
            bool ans2=(prev_block->size - size - size_meta_data >= LARGE_KB);
            if (ans1&& ans2)
            {
                split_block(prev_block, size);

                num_free_blocks++;
                num_free_bytes += prev_block->next->size;
                num_allocated_blocks++;
                num_allocated_bytes -= size_meta_data;
                num_metadata_bytes += size_meta_data;
            }
            return block_addr_from_meta(prev_block);
        }
    }

    //wild case
    if(tail == old_meta_ptr){
        tail->is_free = true;
    }
    size_t old_ptr_size = old_meta_ptr->size;
    void *dest = smalloc(size);
    if (dest == nullptr)
    {
        return nullptr;
    }
    if(dest == block_addr_from_meta(tail)&&(tail == old_meta_ptr)) {

        num_free_blocks++;
        num_free_bytes += old_ptr_size;
        return oldp;
    }

    memmove(dest, oldp, old_meta_ptr->size);
    sfree(oldp);
    return dest;
}

size_t _num_free_blocks()
{
    return num_free_blocks;
}

size_t _num_free_bytes()
{
    return num_free_bytes;
}

size_t _num_allocated_blocks()
{
    return num_allocated_blocks;
}

size_t _num_allocated_bytes()
{
    return num_allocated_bytes;
}

size_t _num_meta_data_bytes()
{
    return num_metadata_bytes;
}

size_t _size_meta_data()
{
    return size_meta_data;
}
