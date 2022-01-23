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

void* mmap_srealloc(void* oldp, size_t size)
{
    MetaData* tmp_oldp = (MetaData*)oldp - 1;
    MetaData* old_meta_data_pointer = tmp_oldp;

    int counter = 0;
    bool cond1 = (old_meta_data_pointer->next != nullptr);
    if (cond1)
    {
        MetaData* old_meta_data_pointer_next =old_meta_data_pointer->next;
        old_meta_data_pointer_next->prev = old_meta_data_pointer->prev;
        counter++;
    }

    bool cond2 = (old_meta_data_pointer->prev != nullptr);
    if (cond2)
    {
        MetaData* old_meta_data_pointer_prev =old_meta_data_pointer->prev;
        old_meta_data_pointer_prev->next = old_meta_data_pointer->next;
        counter++;
    }
    else
    {
        MetaData* old_meta_data_pointer_next = old_meta_data_pointer->next;
        mmap_list = old_meta_data_pointer_next;
        counter++;
    }

    size_t parameter_to_mmap_smalloc = size;
    void* new_pointer = mmap_smalloc(parameter_to_mmap_smalloc);
    size_t old_meta_data_pointer_size = old_meta_data_pointer->size;
    bool cond3 = (size < old_meta_data_pointer_size);
    if (cond3)
    {
        counter++;
        memmove(new_pointer, oldp, size);
    }
    else
    {
        /// cond3 ==0
        counter--;
        size_t old_meta_data_pointer_size = old_meta_data_pointer->size;
        memmove(new_pointer, oldp, old_meta_data_pointer_size);
    }
    size_t old_meta_data_pointer_size_PLUS_MD_SIZE = old_meta_data_pointer->size + MD_SIZE;
    munmap(oldp, old_meta_data_pointer_size_PLUS_MD_SIZE);
    return new_pointer;
}



void* smalloc(size_t size) {
    bool cond1 =(size <= MIN_SIZE);
    bool cond2 =(size > MAX_SIZE);
    if (cond1 || cond2)
        return nullptr;

    bool cond3 = (size >= LARGE_ALLOC);
    if (cond3){
        return mmap_smalloc(size);
    }
    if (memory_list != nullptr)
    {
        int bin_size = 128;
        for (int index = histIndex(size); index < bin_size; index++)
        {
            MetaData* pMetaData = histogram[index];
            while (pMetaData != nullptr)
            {
                size_t meta_data_size = pMetaData->size;
                if (meta_data_size >= size)
                {
                    pMetaData->is_free = false;
                    histRemove(pMetaData);
                    split(pMetaData, size);
                    return pMetaData + 1;
                }
                pMetaData = pMetaData->next_free;
            }
        }

        int block_counter = 0;
        MetaData* wild_chunk = memory_list;
        //todo: make sure this is the wild chunk
        while (wild_chunk->next)
        {
            wild_chunk = wild_chunk->next;
            block_counter++;
        }
        if (wild_chunk->is_free)
        {
            MetaData* block_before_wc = wild_chunk->prev;
            if (block_before_wc != nullptr && block_before_wc->is_free) ///merge down if we can
            {
                void* new_heap_pointer = sbrk(size - wild_chunk->size - block_before_wc->size - sizeof(MetaData));
                if (new_heap_pointer == (void*)(-1))
                    return nullptr;

                histRemove(block_before_wc);
                histRemove(wild_chunk);

                block_before_wc->is_free = false;
                wild_chunk->is_free = false;

                block_before_wc->next = nullptr;
                block_before_wc->size = size;

                return block_before_wc + 1;
            }
            ///
            /// in case we can't merge down
            ///

            void* new_heap_pointer = sbrk(size - wild_chunk->size);
            if (new_heap_pointer == (void*)(-1)) {
                return nullptr;
            }histRemove(wild_chunk);
            wild_chunk->is_free = false;
            wild_chunk->size = size;
            return wild_chunk + 1;
        }
    }

    int wanted_size = size + sizeof(MetaData);
    MetaData* new_meta_data = (MetaData*)sbrk(wanted_size);
    if (new_meta_data == (void*)(-1))
    {
        return nullptr;
    }

    new_meta_data->is_free = false;
    new_meta_data->size = size;
    new_meta_data->next = new_meta_data->prev = nullptr;

    if (memory_list == nullptr)
    {
        memory_list = new_meta_data;
    }
    else
    {
        int counter = 0;
        MetaData* final_md_in_list = memory_list;
        ///note: this pointer is not yet the last one
        ///      but we gonna make him the lsat one
        while (final_md_in_list->next)
        {
            counter++;
            final_md_in_list = final_md_in_list->next;
        }
        new_meta_data->prev = final_md_in_list;
        final_md_in_list->next = new_meta_data;
    }


    return new_meta_data + 1;
}

void* scalloc(size_t num, size_t size) {
    void* address_of_allocation = smalloc(num * size);

    if (address_of_allocation == nullptr) {//make sure the allocation did not fail
        return nullptr;
    }
    else {
        size_t godel = num * size;
        int wanted_size = 0;
        return memset(address_of_allocation, wanted_size, godel);}
}

void sfree(void* p) {
    if (p == nullptr) {
        return; }
    MetaData* meta_data = (MetaData*)p - 1;

    bool cond1 = (meta_data->size < LARGE_ALLOC);


    if (meta_data->is_free) {
        return; }

    else if (cond1)
    {
        meta_data->is_free = true;
        histInsert(meta_data);
        merge(meta_data);
    }
    else
    {

        bool has_prev = meta_data->prev != nullptr;
        if (has_prev)
        {
            meta_data->prev->next = meta_data->next;
        }
        else
        {
            MetaData*next = meta_data->next;
            mmap_list = next;
        }
        bool has_next = meta_data->next != nullptr;
        if (has_next)
        {
            meta_data->next->prev = meta_data->prev;
        }
        size_t size_md = meta_data->size + MD_SIZE;
        munmap(p, size_md);
    }
}

void* srealloc(void* oldp, size_t size) {
    bool cond1 = (size <= MIN_SIZE);
    bool cond2 = (size > MAX_SIZE);
    if (cond1 || cond2) {
        return nullptr;
    }

    bool oldP_is_null =(oldp == nullptr);
    if (oldP_is_null) {
        return smalloc(size); }

    bool valid_size =(size >= LARGE_ALLOC);
    if (valid_size) {
        return mmap_srealloc(oldp, size); }

    MetaData* old_meta_data = (MetaData*) oldp - 1;

    MetaData* after_meta_data = old_meta_data->next;
    MetaData* before_meta_data = old_meta_data->prev;

    bool before_meta_data_is_free = before_meta_data != nullptr && before_meta_data->is_free ;
    bool before_meta_data_has_enought_size = before_meta_data != nullptr && before_meta_data->size + old_meta_data->size + MD_SIZE >= size;

    bool after_meta_data_is_free = after_meta_data != nullptr && after_meta_data->is_free;
    bool after_meta_data_has_enought_size = after_meta_data != nullptr && after_meta_data->size + old_meta_data->size + MD_SIZE >= size;

    size_t size_of_old_md = old_meta_data->size;
    if (size_of_old_md >= size)
    {
        old_meta_data->is_free = false;
        ///has enough size so split
        split(old_meta_data, size);
        return oldp;
    }

    else if (before_meta_data_is_free && before_meta_data_has_enought_size)
    {
        histRemove(before_meta_data);
        before_meta_data->next = old_meta_data->next;
        if (old_meta_data->next != nullptr)
        {
            ///set prev of next if we can
            old_meta_data->next->prev = before_meta_data;
        }
        before_meta_data->is_free = false;
        before_meta_data->size += old_meta_data->size + MD_SIZE;

        memmove(before_meta_data + 1, oldp, old_meta_data->size); ///move the data to where we want
        split(before_meta_data, size);
        return before_meta_data + 1;
    }

    else if (after_meta_data_is_free && after_meta_data_has_enought_size)
    {
        histRemove(after_meta_data);
        old_meta_data->next = after_meta_data->next;
        if (after_meta_data->next != nullptr)
        {
            ///set prev of next if we can
            after_meta_data->next->prev = old_meta_data;
        }
        after_meta_data->is_free = false;
        old_meta_data->size += after_meta_data->size + MD_SIZE;

        split(old_meta_data, size);
        return old_meta_data + 1;
    }

    else if (before_meta_data_is_free && after_meta_data_is_free &&
             before_meta_data->size + old_meta_data->size + after_meta_data->size + 2*MD_SIZE >= size)
    {

        histRemove(after_meta_data);
        histRemove(before_meta_data);

        before_meta_data->next = after_meta_data->next;
        before_meta_data->is_free = after_meta_data->is_free = false;

        if (after_meta_data->next != nullptr)
        {
            after_meta_data->next->prev = before_meta_data;
        }
        before_meta_data->size += old_meta_data->size + after_meta_data->size + 2*MD_SIZE;

        memmove(before_meta_data + 1, oldp, old_meta_data->size);
        split(before_meta_data, size);
        return before_meta_data + 1;
    }

    else if (old_meta_data->next == nullptr) {
        if (before_meta_data != nullptr && before_meta_data->is_free){ ///merge down if we can
            void* enlarge = sbrk(size - old_meta_data->size - before_meta_data->size - sizeof(MetaData));
            if (enlarge == (void*)(-1))
                return nullptr;

            histRemove(before_meta_data);
            histRemove(old_meta_data);

            before_meta_data->is_free = false;
            old_meta_data->is_free = false;

            before_meta_data->next = nullptr;
            before_meta_data->size = size;

            memmove(before_meta_data + 1, oldp, old_meta_data->size);

            return before_meta_data + 1;
        }

        void* new_heap_pointer = sbrk(size - old_meta_data->size);
        if (new_heap_pointer == (void*)(-1)) {
            return nullptr;
        }

        old_meta_data->size = size;
        return old_meta_data + 1;
    }

    else
    {
        void* address_of_new_allocation = smalloc(size);
        if (address_of_new_allocation == nullptr) {
            return nullptr;}

        memmove(address_of_new_allocation, oldp, old_meta_data->size);
        histInsert(old_meta_data);
        old_meta_data->is_free = true;
        return address_of_new_allocation;
    }
}




size_t _num_free_blocks() {
    size_t block_counter = 0;
    int bin_size = 128;
    for (int ind = 0; ind < bin_size; ind++)
    {
        MetaData* meta_data = histogram[ind];
        while (meta_data != nullptr)
        {
            meta_data = meta_data->next_free;
            block_counter +=1;
        }
    }
    return block_counter;
}

size_t _num_free_bytes()
{
    size_t counter_of_free_bytes = 0;
    int bin_size = 128;
    for (int ind = 0; ind <bin_size; ind++)
    {
        MetaData* meta_data = histogram[ind];
        while (meta_data != nullptr)
        {
            counter_of_free_bytes += meta_data->size;
            meta_data = meta_data->next_free;
        }
    }
    return counter_of_free_bytes;
}

size_t _num_allocated_blocks()
{
    size_t allocated_blocks_counter = 0;

    if (mmap_list != nullptr)
    {
        for (MetaData* meta_data = mmap_list; meta_data != nullptr; meta_data = meta_data->next)
        {
            allocated_blocks_counter++;
        }
    }
    if (memory_list != nullptr)
    {
        for (MetaData* meta_data = memory_list; meta_data != nullptr; meta_data = meta_data->next)
        {
            allocated_blocks_counter++;
        }
    }
    return allocated_blocks_counter;
}

size_t _num_allocated_bytes()
{
    size_t counter_of_allocated_bytes = 0;
    if (memory_list != nullptr)
    {
        for (MetaData* meta_data = memory_list; meta_data != nullptr; meta_data = meta_data->next)
        {
            counter_of_allocated_bytes += meta_data->size;
        }
    }
    if (mmap_list != nullptr)
    {
        for (MetaData* meta_data = mmap_list; meta_data != nullptr; meta_data = meta_data->next)
        {
            counter_of_allocated_bytes += meta_data->size;
        }
    }
    return counter_of_allocated_bytes;
}

size_t _size_meta_data()
{
    return sizeof(MetaData);
}

size_t _num_meta_data_bytes()
{
    return _num_allocated_blocks() * _size_meta_data();
}