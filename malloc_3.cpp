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

int histIndex (size_t size)
{
    /// done
    size_t size_par = size;
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
        int histIndex_md_param_size = histIndex(md_param->size);
        int index_hist = histIndex_md_param_size;

        MetaData* md_param_next_free = md_param->next_free;
        histogram[index_hist] = md_param_next_free;
    }
    bool cond_2 = (md_param->next_free != nullptr);
    if (cond_2)
    {
        MetaData* md_param_prev_free = md_param->prev_free;
        md_param->next_free->prev_free = md_param_prev_free;
    }
    md_param->prev_free = nullptr;
    md_param->next_free = nullptr;
}

void histInsert (MetaData* md)
{
    MetaData* md_param = md;
    size_t md_param_size = md_param->size;
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
        bool is_inserted_flag;
        is_inserted_flag = false;
        MetaData* current_md = slot_hist_by_index;
        while (slot_hist_by_index != nullptr)
        {
            size_t slot_hist_by_index_size = slot_hist_by_index->size;
            bool cond_2 = (slot_hist_by_index_size >= md_param_size);
            if (cond_2)
            {
                MetaData* slot_hist_by_index_prev_free = slot_hist_by_index->prev_free;
                bool cond_3 = (slot_hist_by_index_prev_free == nullptr);
                if (cond_3)
                {
                    MetaData* md_param_cond_3 = md_param;

                    histogram[index_hist] = md_param_cond_3;
                    md_param_cond_3->next_free = slot_hist_by_index;
                    md_param_cond_3->prev_free = nullptr;
                    slot_hist_by_index->prev_free = md_param_cond_3;
                    is_inserted_flag = true ;
                    break;
                }
                else
                {
                    MetaData* md_param_cond_3_else = md_param;
                    MetaData* slot_hist_by_index_prev_free = slot_hist_by_index->prev_free;
                    /// here change md_param to md_param_cond_3_else

                    slot_hist_by_index_prev_free->next_free = md_param_cond_3_else;
                    md_param_cond_3_else->prev_free = slot_hist_by_index_prev_free;
                    int counter_cond_4 = 0;
                    slot_hist_by_index_prev_free = md_param_cond_3_else;
                    md_param_cond_3_else->next_free = slot_hist_by_index ;
                    is_inserted_flag = true;
                    break;
                    counter_cond_4++;
                }
            }
            current_md = slot_hist_by_index ;
            MetaData* slot_hist_by_index_next_free = slot_hist_by_index->next_free;
            slot_hist_by_index = slot_hist_by_index_next_free;
        }

        bool cond_4 = (!is_inserted_flag);
        int counter_4 = 0;
        if (cond_4)
        {
            MetaData* md_param_cond4 = md_param;
            current_md->next_free = md_param_cond4;
            if (counter_4)
            {
                counter_4++;
            }
            md_param_cond4->prev_free = current_md ;
            md_param_cond4->next_free = nullptr;
        }
    }
}

void split(MetaData* metaData, size_t requested_size)
{
    /// split
    /// this function split
    size_t metaData_size_MINUS_requested_size = metaData->size - requested_size;
    int cond_1 = (metaData_size_MINUS_requested_size < (SPLIT_MIN + MD_SIZE));
    if(cond_1) {
        return;
    }

    unsigned long address = (size_t)metaData + MD_SIZE + requested_size;
    MetaData* newMataData = (MetaData*)(address);


    newMataData->next_free = nullptr;

    bool true_bool = true;
    newMataData->is_free = true_bool;

    newMataData->prev_free = nullptr;

    size_t temp = metaData->size - requested_size;
    newMataData->size = temp - MD_SIZE;

    bool cond_2 = (metaData->next != nullptr);
    if (cond_2)
    {
        int counter_cond1 = 0;
        MetaData* metaData_next = metaData->next;
        MetaData* nextMetaData = metaData_next;

        counter_cond1++;
        bool cond_3 = nextMetaData->is_free;
        if (cond_3)
        {
            int counter_cond2 = 0;
            size_t nextMetaData_size = nextMetaData->size;
            size_t nextMetaData_size_PLUS_md_size = MD_SIZE + nextMetaData_size;
            newMataData->size += nextMetaData_size_PLUS_md_size;

            counter_cond2++;
            if (counter_cond2)
            {
                counter_cond2+= 1;
            }

            newMataData->next = nextMetaData->next;

            bool cond_3 = (nextMetaData->next != nullptr);
            if(cond_3)
            {
                nextMetaData->next->prev = newMataData;
            }
            counter_cond2 += 2;
            histRemove(nextMetaData);
        }
        else
        {
            MetaData* nextMetaData_cond2_else = nextMetaData;
            newMataData->next = nextMetaData;
            counter_cond1 += 1;
            nextMetaData->prev = newMataData;
        }
    }

    MetaData* metaData_end = metaData;
    newMataData->prev = metaData_end;

    MetaData* newMataData_end = newMataData;
    metaData->next = newMataData_end;

    int end_counter = 1;
    int end_counter_1 = 1;
    if (end_counter == end_counter_1)
    {
        metaData->size = requested_size;
        histInsert(newMataData);
    }
}


void merge(MetaData* metaData)
{
    /// done
    /// merge
    MetaData* metaData_next = metaData->next;
    MetaData* next_block = metaData_next;

    bool ans1 = (next_block != nullptr);
    if (ans1 && next_block->is_free){
        /// only if cond1 happens
        bool cond2 = 1;
        bool cond3 = 1;

        /// check cond2 and cond3
        if (cond2 == cond3)
        {
            histRemove(metaData);
            histRemove(next_block);
        }

        /// after 2 removes
        size_t next_block_size_PLUS_MD_SIZE = next_block->size + MD_SIZE;
        metaData->size += next_block_size_PLUS_MD_SIZE;

        MetaData* next_block_cond1 = next_block;
        metaData->next = next_block_cond1->next;

        bool cond4 = (next_block->next != nullptr);
        if (cond4)
        {
            /// if cond4 happened
            MetaData* next_block_next = next_block->next;
            next_block_next->prev = metaData;
        }

        histInsert(metaData);
    }


    // Merge with previous block if it's free
    MetaData* previous_Block = metaData->prev;
    int ans2 = (previous_Block != nullptr);
    if (ans2 && previous_Block->is_free) {
        if (ans2)
        {
            histRemove(previous_Block);
            histRemove(metaData);
        }
        size_t metaData_size_PLUS_MD_SIZE = metaData->size + MD_SIZE;
        previous_Block->size += metaData_size_PLUS_MD_SIZE;

        /// check if works
        previous_Block->next = metaData->next;

        bool cond6 = (metaData->next != nullptr);
        if (cond6)
        {
            metaData->next->prev = previous_Block;
        }

        /// success
        histInsert(previous_Block);
    }
}


void* mmap_smalloc(size_t size)
{

    void* mm_block = mmap(NULL, size + MD_SIZE, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    bool cond1 = (mm_block == MAP_FAILED);
    if (cond1)
    {
        return nullptr;
    }

    /// cond1 = 0
    MetaData* metaData = (MetaData*)mm_block;
    metaData->size = size;

    bool false_flag = false;
    metaData->is_free = false_flag;

    bool cond2 = !mmap_list;
    if (cond2)
    {
        mmap_list = metaData;
        metaData->next =  nullptr;
        cond2 ++;
        metaData->prev = nullptr;
    }
    else
    {
        /// cond2 = 0
        MetaData* md_cond2 = mmap_list;
        /// get forward with md
        while (md_cond2->next)
        {
            md_cond2 = md_cond2->next;
        }

        metaData->prev = md_cond2;

        MetaData* metaData_cond2 = metaData;
        md_cond2->next = metaData_cond2;
    }

    MetaData* return_value = metaData;
    return_value += 1;
    return return_value;
}

void* mmap_srealloc(void* oldp, size_t size) {
    MetaData* old_md = (MetaData*)oldp - 1;

    if (old_md->next != nullptr) {
        old_md->next->prev = old_md->prev;
    }
    if (old_md->prev != nullptr) {
        old_md->prev->next = old_md->next;
    } else {
        mmap_list = old_md->next;
    }
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