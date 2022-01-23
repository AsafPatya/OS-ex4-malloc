#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sys/mman.h>

#define MIN_SIZE 0
#define MAX_SIZE 100000000
#define SPLIT_MIN 128
#define KB 1024
#define LARGE_ALLOC 128 * KB
#define MD_SIZE sizeof(MetaData)

using std::memset;
using std::memmove;

struct MetaData {
    size_t size;
    bool is_free;
    MetaData* next;
    MetaData* prev;
    MetaData* next_free;
    MetaData* prev_free;
};

MetaData* memory_list = nullptr;
MetaData* mmap_list = nullptr;
MetaData* histogram[128];

/* ================= Helper Functions ================== */

int histIndex (size_t size)
{
    /// done
    int size_par = size;
    int index = 0;
    int const_128 = 128;
    while (index < const_128)
    {
        int index_mul_KB = index*KB;
        if (index_mul_KB <= size_par && size_par < (1+index)*KB){
            return index ;
        }
        index = index + 1;
    }
    int return_value = index-1;
    return return_value;
}

void histRemove(MetaData* md)
{
    /// done
    MetaData* md_param = md;
    bool cond_1 = (md_param->prev_free != nullptr);
    if (cond_1)
    {
        md_param->prev_free->next_free = md_param->next_free;
    }
    else
    {
        int index_hist = histIndex(md_param->size);
        histogram[index_hist] = md_param->next_free;
    }
    bool cond_2 = (md_param->next_free != nullptr);
    if (cond_2)
    {
        md_param->next_free->prev_free = md_param->prev_free;
    }
    md_param->prev_free = nullptr;
    md_param->next_free = nullptr;
}

void histInsert (MetaData* md)
{
    MetaData* md_param = md;
    int md_param_size = md_param->size;
    int index_hist = histIndex(md_param_size);
    MetaData* slot_hist_by_index = histogram[index_hist];

    bool cond_1 = (slot_hist_by_index == nullptr);
    if (cond_1)
    {
        histogram[index_hist] = md_param;
        md_param->next_free = nullptr;
        md_param->prev_free = nullptr;
    }
    else
    {
        bool is_inserted = false;
        MetaData* current_md = slot_hist_by_index;
        while (slot_hist_by_index != nullptr) {
            int slot_hist_by_index_size = slot_hist_by_index->size;
            bool cond_2 = (slot_hist_by_index_size >= md_param_size);
            if (cond_2)
            {
                MetaData* slot_hist_by_index_prev_free = slot_hist_by_index->prev_free;
                bool cond_3 = (slot_hist_by_index_prev_free == nullptr);
                if (cond_3)
                {
                    histogram[index_hist] = md_param;
                    md_param->next_free = slot_hist_by_index;
                    md_param->prev_free = nullptr;
                    slot_hist_by_index->prev_free = md_param;
                    is_inserted = true ;
                    break;
                }
                else {
                    slot_hist_by_index->prev_free->next_free = md_param;
                    md_param->prev_free = slot_hist_by_index->prev_free;
                    slot_hist_by_index->prev_free = md_param;
                    md_param->next_free = slot_hist_by_index ;
                    is_inserted = true;
                    break;
                }
            }
            current_md = slot_hist_by_index ;
            slot_hist_by_index = slot_hist_by_index->next_free;
        }
        if (!is_inserted) {
            current_md->next_free = md_param;
            md_param->prev_free = current_md ;
            md_param->next_free = nullptr;
        }
    }
}

void split(MetaData* metaData, size_t requested_size) {
    if(metaData->size - requested_size < SPLIT_MIN + MD_SIZE) {
        return;
    }

    MetaData* newMataData = (MetaData*)((size_t)metaData + MD_SIZE + requested_size);
    newMataData->is_free = true;
    newMataData->next_free = nullptr;
    newMataData->prev_free = nullptr;
    newMataData->size = metaData->size - requested_size - MD_SIZE;

    if (metaData->next != nullptr){
        MetaData* nextMetaData = metaData->next;
        if (nextMetaData->is_free){
            newMataData->size += MD_SIZE + nextMetaData->size;
            newMataData->next = nextMetaData->next;
            if(nextMetaData->next != nullptr){
                nextMetaData->next->prev = newMataData;
            }
            histRemove(nextMetaData);
        }
        else{
            newMataData->next = nextMetaData;
            nextMetaData->prev = newMataData;
        }
    }

    newMataData->prev = metaData;
    metaData->next = newMataData;
//    newMataData->next = metaData->next;
//
//    if (newMataData->next != nullptr) {
//        newMataData->next->prev = newMataData;
//    }
    metaData->size = requested_size;
    histInsert(newMataData);
}

void merge(MetaData* metaData) {
    // Merge with next block if it's free
    MetaData* next_block = metaData->next;
    if (next_block != nullptr && next_block->is_free) {
        histRemove(metaData);
        histRemove(next_block);
        metaData->size += next_block->size + MD_SIZE;
        metaData->next = next_block->next;
        if (next_block->next != nullptr) {
            next_block->next->prev = metaData;
        }
        histInsert(metaData);
    }

    // Merge with previous block if it's free
    MetaData* prev_block = metaData->prev;
    if (prev_block != nullptr && prev_block->is_free) {
        histRemove(prev_block);
        histRemove(metaData);
        prev_block->size += metaData->size + MD_SIZE;
        prev_block->next = metaData->next;
        if (metaData->next != nullptr) {
            metaData->next->prev = prev_block;
        }
        histInsert(prev_block);
    }
}

void* mmap_smalloc(size_t size) {
    // Allocate large memory for meta-data and 'size' bytes using mmap
    void* mm_block = mmap(NULL, size + MD_SIZE, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mm_block == MAP_FAILED)
        return nullptr;

    MetaData* metaData = (MetaData*)mm_block;
    metaData->size = size;
    metaData->is_free = false;

    // Insert new block to mmap_list
    if (!mmap_list) {
        mmap_list = metaData;
        metaData->next = metaData->prev = nullptr;
    }
    else {
        MetaData* md = mmap_list;
        while (md->next) {
            md = md->next;
        }
        metaData->prev = md;
        md->next = metaData;
    }

    return metaData + 1;
}

void* mmap_srealloc(void* oldp, size_t size) {
    MetaData* old_md = (MetaData*)oldp - 1;

    // Remove old block from mmap list
    if (old_md->next != nullptr) {
        old_md->next->prev = old_md->prev;
    }
    if (old_md->prev != nullptr) {
        old_md->prev->next = old_md->next;
    } else {
        mmap_list = old_md->next;
    }
    // Reallocate memory for new size and free old block 
    void* newp = mmap_smalloc(size);
    if (size < old_md->size) {
        memmove(newp, oldp, size);
    } else {
        memmove(newp, oldp, old_md->size);
    }
    munmap(oldp, old_md->size + MD_SIZE);
    return newp;
}

/* ================ Upgraded Functions ================= */

void* smalloc(size_t size) {
    if (size <= MIN_SIZE || size > MAX_SIZE)
        return nullptr;

    if (size >= LARGE_ALLOC)
        return mmap_smalloc(size);

    // First, search for free space in memory list
    if (memory_list) {
        // Check if histogram has a free block with enough space
        for (int i = histIndex(size); i < 128; i++) {
            MetaData* md = histogram[i];
            while (md != nullptr) {
                if (md->size >= size) {
                    md->is_free = false;
                    histRemove(md);
                    split(md, size);
                    return md + 1;
                }
                md = md->next_free;
            }
        }

        // Check if wilderness chunck is free
        MetaData* wild = memory_list;
        while (wild->next) {
            wild = wild->next;
        }
        if (wild->is_free /*true dat*/) {
            MetaData* prev_block = wild->prev;
            if (prev_block != nullptr && prev_block->is_free){ ///merge down if we can
                void* enlarge = sbrk(size - wild->size - prev_block->size - sizeof(MetaData));
                if (enlarge == (void*)(-1))
                    return nullptr;

                histRemove(prev_block);
                histRemove(wild);

                prev_block->is_free = false;
                wild->is_free = false;

                prev_block->next = nullptr;
                prev_block->size = size;

                return prev_block + 1;
            }
            histRemove(wild);
            wild->is_free = false; //bummer
            void* enlarge = sbrk(size - wild->size);
            if (enlarge == (void*)(-1))
                return nullptr;

            wild->size = size;
            return wild + 1;
        }
    }

    // If not enough free space was found, allocate new memory
    MetaData* metaData = (MetaData*)sbrk(size + sizeof(MetaData));
    if (metaData == (void*)(-1)) {
        return nullptr;
    }

    metaData->size = size;
    metaData->is_free = false;
    metaData->next = metaData->prev = nullptr;

    // Add the allocated meta-data to memory list
    if (!memory_list) {
        memory_list = metaData;
    }
    else {
        MetaData* last = memory_list;
        while (last->next) {
            last = last->next;
        }
        last->next = metaData;
        metaData->prev = last;
    }

    return metaData + 1;
}

void* scalloc(size_t num, size_t size) {
    // First, allocate memory using smalloc
    void* alloc_addr = smalloc(num * size);

    if (!alloc_addr)
        return nullptr;

        // Then, if allocation succeeds, reset the block
    else
        return memset(alloc_addr, 0, num * size);

}

void sfree(void* p) {
    if (!p) return;

    MetaData* md = (MetaData*)p - 1;
    if (md->is_free) return;

        // If p is in memory_list, add the allocated block to free histogram
    else if (md->size < LARGE_ALLOC) {
        md->is_free = true;
        histInsert(md);
        merge(md);
    }
        // Else if p is in mmap_list, free the allocated block using munmap
    else {
        if (md->next != nullptr) {
            md->next->prev = md->prev;
        }
        if (md->prev != nullptr) {
            md->prev->next = md->next;
        } else {
            mmap_list = md->next;
        }
        munmap(p, md->size + MD_SIZE);
    }
}

void* srealloc(void* oldp, size_t size) {
    if (size <= MIN_SIZE || size > MAX_SIZE)
        return nullptr;

    // If oldp is null, allocate memory for 'size' bytes and return a pointer to it
    if (oldp == nullptr) return smalloc(size);

    if (size >= LARGE_ALLOC) return mmap_srealloc(oldp, size);

    MetaData* old_md = (MetaData*) oldp - 1;
    MetaData* prev_block = old_md->prev;
    MetaData* next_block = old_md->next;

    // Check if old block has enough memory to support the new block size
    if (old_md->size >= size) {
        old_md->is_free = false;
        split(old_md, size);
        return oldp;
    }

        // If not, check if merging with PREVIOUS block is sufficient 
    else if (prev_block != nullptr && prev_block->is_free &&
             prev_block->size + old_md->size + MD_SIZE >= size) {
        // Remove previous block from free histogram and merge with old block
        histRemove(prev_block);
        prev_block->is_free = false;
        prev_block->size += old_md->size + MD_SIZE;
        prev_block->next = old_md->next;
        if (old_md->next != nullptr) {
            old_md->next->prev = prev_block;
        }
        // Copy the data, then split the merged block
        memmove(prev_block + 1, oldp, old_md->size);
        split(prev_block, size);
        return prev_block + 1;
    }

        // If not, check if merging with NEXT block is sufficient 
    else if (next_block != nullptr && next_block->is_free &&
             next_block->size + old_md->size + MD_SIZE >= size) {
        // Remove next block from free histogram and merge with old block
        histRemove(next_block);
        next_block->is_free = false;
        old_md->size += next_block->size + MD_SIZE;
        old_md->next = next_block->next;
        if (next_block->next != nullptr) {
            next_block->next->prev = old_md;
        }
        // Split the merged block
        split(old_md, size);
        return old_md + 1;
    }

        // If not, check if merging with BOTH adjacent blocks is sufficient 
    else if (prev_block != nullptr && prev_block->is_free &&
             next_block != nullptr && next_block->is_free &&
             prev_block->size + old_md->size + next_block->size + 2*MD_SIZE >= size) {
        // Remove adjacent blocks from free histogram and merge with old block
        histRemove(prev_block);
        histRemove(next_block);
        prev_block->is_free = next_block->is_free = false;
        prev_block->size += old_md->size + next_block->size + 2*MD_SIZE;
        prev_block->next = next_block->next;
        if (next_block->next != nullptr) {
            next_block->next->prev = prev_block;
        }
        // Copy the data, then split the merged block
        memmove(prev_block + 1, oldp, old_md->size);
        split(prev_block, size);
        return prev_block + 1;
    }

        // If not, check if reallocation is in wilderness block and enlarge it
    else if (old_md->next == nullptr) {
        if (prev_block != nullptr && prev_block->is_free){ ///merge down if we can
            void* enlarge = sbrk(size - old_md->size - prev_block->size - sizeof(MetaData));
            if (enlarge == (void*)(-1))
                return nullptr;

            histRemove(prev_block);
            histRemove(old_md);

            prev_block->is_free = false;
            old_md->is_free = false;

            prev_block->next = nullptr;
            prev_block->size = size;

            memmove(prev_block + 1, oldp, old_md->size);

            return prev_block + 1;
        }

        void* enlarge = sbrk(size - old_md->size);
        if (enlarge == (void*)(-1))
            return nullptr;

        old_md->size = size;
        return old_md + 1;
    }

        // If not, allocate memory using smalloc
    else {
        void* realloc_addr = smalloc(size);
        if (!realloc_addr)
            return nullptr;

        // Copy the data, then free the old memory using sfree
        memmove(realloc_addr, oldp, old_md->size);
        histInsert(old_md);
        old_md->is_free = true;
        return realloc_addr;
    }
}


size_t _num_free_blocks() {
    size_t free_blocks = 0;
    for (int i = 0; i < 128; i++) {
        MetaData* md = histogram[i];
        while (md != nullptr) {
            free_blocks++;
            md = md->next_free;
        }
    }
    return free_blocks;
}

size_t _num_free_bytes() {
    size_t free_bytes = 0;
    for (int i = 0; i < 128; i++) {
        MetaData* md = histogram[i];
        while (md != nullptr) {
            free_bytes += md->size;
            md = md->next_free;
        }
    }
    return free_bytes;
}

size_t _num_allocated_blocks() {
    size_t allocated_blocks = 0;
    if (memory_list) {
        for (MetaData* md = memory_list; md != nullptr; md = md->next) {
            allocated_blocks++;
        }
    }
    if (mmap_list) {
        for (MetaData* md = mmap_list; md != nullptr; md = md->next) {
            allocated_blocks++;
        }
    }
    return allocated_blocks;
}

size_t _num_allocated_bytes() {
    size_t allocated_bytes = 0;
    if (memory_list) {
        for (MetaData* md = memory_list; md != nullptr; md = md->next) {
            allocated_bytes += md->size;
        }
    }
    if (mmap_list) {
        for (MetaData* md = mmap_list; md != nullptr; md = md->next) {
            allocated_bytes += md->size;
        }
    }
    return allocated_bytes;
}

size_t _size_meta_data() {
    return sizeof(MetaData);
}

size_t _num_meta_data_bytes() {
    return _num_allocated_blocks() * _size_meta_data();
}