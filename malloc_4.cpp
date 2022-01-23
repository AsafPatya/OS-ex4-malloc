#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sys/mman.h>

#define MINIMUM_SIZE 0
#define MAXIMUM_SIZE 100000000
#define SPLIT_MINIMUN 128
#define KILO_BYTE 1024
#define LARGE_ALLOCATION 128 * KILO_BYTE
#define METADATA_SIZE sizeof(Meta_Data_Struct)
#define bins_size 128

using std::memset;
using std::memmove;

struct Meta_Data_Struct {
    size_t md_size;
    bool md_is_free;
    Meta_Data_Struct* md_next;
    Meta_Data_Struct* md_prev;
    Meta_Data_Struct* md_next_free;
    Meta_Data_Struct* md_prev_free;
};

Meta_Data_Struct* bins[bins_size];

Meta_Data_Struct* list_of_memory_allocation = nullptr;
Meta_Data_Struct* list_of_mmap = nullptr;



int bin_Index (size_t param_size)
{
    /// done
    size_t size_par = param_size;
    int index = 0;
    int const_128 = 128;
    while (index < const_128)
    {
        int index_mul_KB = index*KILO_BYTE;
        if (index_mul_KB <= size_par && size_par < (1+index)*KILO_BYTE){
            return index ;
        }
        index = index + 1;
    }
    int return_value = index-1;
    return return_value;
}

void bin_Insert (Meta_Data_Struct* meta_data_pointer)
{
    Meta_Data_Struct* md_param = meta_data_pointer;
    size_t md_param_size = md_param->md_size;
    int index_hist = bin_Index(md_param_size);
    Meta_Data_Struct* slot_hist_by_index = bins[index_hist];

    bool cond_1 = (slot_hist_by_index == nullptr);
    if (cond_1)
    {
        bins[index_hist] = md_param;
        md_param->md_next_free = nullptr;
        md_param->md_prev_free = nullptr;
    }
    else
    {
        bool is_inserted_flag;
        is_inserted_flag = false;
        Meta_Data_Struct* current_md = slot_hist_by_index;
        while (slot_hist_by_index != nullptr)
        {
            size_t slot_hist_by_index_size = slot_hist_by_index->md_size;
            bool cond_2 = (slot_hist_by_index_size >= md_param_size);
            if (cond_2)
            {
                Meta_Data_Struct* slot_hist_by_index_prev_free = slot_hist_by_index->md_prev_free;
                bool cond_3 = (slot_hist_by_index_prev_free == nullptr);
                if (cond_3)
                {
                    Meta_Data_Struct* md_param_cond_3 = md_param;

                    bins[index_hist] = md_param_cond_3;
                    md_param_cond_3->md_next_free = slot_hist_by_index;
                    md_param_cond_3->md_prev_free = nullptr;
                    slot_hist_by_index->md_prev_free = md_param_cond_3;
                    is_inserted_flag = true ;
                    break;
                }
                else
                {
                    Meta_Data_Struct* md_param_cond_3_else = md_param;
                    Meta_Data_Struct* slot_hist_by_index_prev_free = slot_hist_by_index->md_prev_free;
                    /// here change md_param to md_param_cond_3_else

                    slot_hist_by_index_prev_free->md_next_free = md_param_cond_3_else;
                    md_param_cond_3_else->md_prev_free = slot_hist_by_index_prev_free;
                    int counter_cond_4 = 0;
                    slot_hist_by_index_prev_free = md_param_cond_3_else;
                    md_param_cond_3_else->md_next_free = slot_hist_by_index ;
                    is_inserted_flag = true;
                    break;
                    counter_cond_4++;
                }
            }
            current_md = slot_hist_by_index ;
            Meta_Data_Struct* slot_hist_by_index_next_free = slot_hist_by_index->md_next_free;
            slot_hist_by_index = slot_hist_by_index_next_free;
        }

        bool cond_4 = (!is_inserted_flag);
        int counter_4 = 0;
        if (cond_4)
        {
            Meta_Data_Struct* md_param_cond4 = md_param;
            current_md->md_next_free = md_param_cond4;
            if (counter_4)
            {
                counter_4++;
            }
            md_param_cond4->md_prev_free = current_md ;
            md_param_cond4->md_next_free = nullptr;
        }
    }
}

void bin_Remove(Meta_Data_Struct* meta_data_pointer)
{
    /// done
    Meta_Data_Struct* md_param = meta_data_pointer;
    bool cond_1 = (md_param->md_prev_free != nullptr);
    if (cond_1)
    {
        md_param->md_prev_free->md_next_free = md_param->md_next_free;
    }
    else
    {
        int histIndex_md_param_size = bin_Index(md_param->md_size);
        int index_hist = histIndex_md_param_size;

        Meta_Data_Struct* md_param_next_free = md_param->md_next_free;
        bins[index_hist] = md_param_next_free;
    }
    bool cond_2 = (md_param->md_next_free != nullptr);
    if (cond_2)
    {
        Meta_Data_Struct* md_param_prev_free = md_param->md_prev_free;
        md_param->md_next_free->md_prev_free = md_param_prev_free;
    }
    md_param->md_prev_free = nullptr;
    md_param->md_next_free = nullptr;
}






void* mmap_smalloction(size_t md_size)
{

    void* mm_block = mmap(NULL, md_size + METADATA_SIZE, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    bool cond1 = (mm_block == MAP_FAILED);
    if (cond1)
    {
        return nullptr;
    }

    /// cond1 = 0
    Meta_Data_Struct* metaData = (Meta_Data_Struct*)mm_block;
    metaData->md_size = md_size;

    bool false_flag = false;
    metaData->md_is_free = false_flag;

    bool cond2 = !list_of_mmap;
    if (cond2)
    {
        list_of_mmap = metaData;
        metaData->md_next =  nullptr;
        cond2 ++;
        metaData->md_prev = nullptr;
    }
    else
    {
        /// cond2 = 0
        Meta_Data_Struct* md_cond2 = list_of_mmap;
        /// get forward with md
        while (md_cond2->md_next)
        {
            md_cond2 = md_cond2->md_next;
        }

        metaData->md_prev = md_cond2;

        Meta_Data_Struct* metaData_cond2 = metaData;
        md_cond2->md_next = metaData_cond2;
    }

    Meta_Data_Struct* return_value = metaData;
    return_value += 1;
    return return_value;
}

void merge_not_in_use(Meta_Data_Struct* meta_data_ptr)
{
    /// done
    /// merge
    Meta_Data_Struct* metaData_next = meta_data_ptr->md_next;
    Meta_Data_Struct* next_block = metaData_next;

    bool ans1 = (next_block != nullptr);
    if (ans1 && next_block->md_is_free){
        /// only if cond1 happens
        bool cond2 = 1;
        bool cond3 = 1;

        /// check cond2 and cond3
        if (cond2 == cond3)
        {
            bin_Remove(meta_data_ptr);
            bin_Remove(next_block);
        }

        /// after 2 removes
        size_t next_block_size_PLUS_MD_SIZE = next_block->md_size + METADATA_SIZE;
        meta_data_ptr->md_size += next_block_size_PLUS_MD_SIZE;

        Meta_Data_Struct* next_block_cond1 = next_block;
        meta_data_ptr->md_next = next_block_cond1->md_next;

        bool cond4 = (next_block->md_next != nullptr);
        if (cond4)
        {
            /// if cond4 happened
            Meta_Data_Struct* next_block_next = next_block->md_next;
            next_block_next->md_prev = meta_data_ptr;
        }

        bin_Insert(meta_data_ptr);
    }


    // Merge with previous block if it's free
    Meta_Data_Struct* previous_Block = meta_data_ptr->md_prev;
    int ans2 = (previous_Block != nullptr);
    if (ans2 && previous_Block->md_is_free) {
        if (ans2)
        {
            bin_Remove(previous_Block);
            bin_Remove(meta_data_ptr);
        }
        size_t metaData_size_PLUS_MD_SIZE = meta_data_ptr->md_size + METADATA_SIZE;
        previous_Block->md_size += metaData_size_PLUS_MD_SIZE;

        /// check if works
        previous_Block->md_next = meta_data_ptr->md_next;

        bool cond6 = (meta_data_ptr->md_next != nullptr);
        if (cond6)
        {
            meta_data_ptr->md_next->md_prev = previous_Block;
        }

        /// success
        bin_Insert(previous_Block);
    }
}

void split_block_by_size(Meta_Data_Struct* meta_data_ptr, size_t size)
{
    /// split
    /// this function split
    size_t metaData_size_MINUS_requested_size = meta_data_ptr->md_size - size;
    int cond_1 = (metaData_size_MINUS_requested_size < (SPLIT_MINIMUN + METADATA_SIZE));
    if(cond_1) {
        return;
    }

    unsigned long address = (size_t)meta_data_ptr + METADATA_SIZE + size;
    Meta_Data_Struct* newMataData = (Meta_Data_Struct*)(address);


    newMataData->md_next_free = nullptr;

    bool true_bool = true;
    newMataData->md_is_free = true_bool;

    newMataData->md_prev_free = nullptr;

    size_t temp = meta_data_ptr->md_size - size;
    newMataData->md_size = temp - METADATA_SIZE;

    bool cond_2 = (meta_data_ptr->md_next != nullptr);
    if (cond_2)
    {
        int counter_cond1 = 0;
        Meta_Data_Struct* metaData_next = meta_data_ptr->md_next;
        Meta_Data_Struct* nextMetaData = metaData_next;

        counter_cond1++;
        bool cond_3 = nextMetaData->md_is_free;
        if (cond_3)
        {
            int counter_cond2 = 0;
            size_t nextMetaData_size = nextMetaData->md_size;
            size_t nextMetaData_size_PLUS_md_size = METADATA_SIZE + nextMetaData_size;
            newMataData->md_size += nextMetaData_size_PLUS_md_size;

            counter_cond2++;
            if (counter_cond2)
            {
                counter_cond2+= 1;
            }

            newMataData->md_next = nextMetaData->md_next;

            bool cond_3 = (nextMetaData->md_next != nullptr);
            if(cond_3)
            {
                nextMetaData->md_next->md_prev = newMataData;
            }
            counter_cond2 += 2;
            bin_Remove(nextMetaData);
        }
        else
        {
            Meta_Data_Struct* nextMetaData_cond2_else = nextMetaData;
            newMataData->md_next = nextMetaData;
            counter_cond1 += 1;
            nextMetaData->md_prev = newMataData;
        }
    }

    Meta_Data_Struct* metaData_end = meta_data_ptr;
    newMataData->md_prev = metaData_end;

    Meta_Data_Struct* newMataData_end = newMataData;
    meta_data_ptr->md_next = newMataData_end;

    int end_counter = 1;
    int end_counter_1 = 1;
    if (end_counter == end_counter_1)
    {
        meta_data_ptr->md_size = size;
        bin_Insert(newMataData);
    }
}

void* mmap_srealloction(void* old_ptr, size_t param_size)
{
    Meta_Data_Struct* tmp_oldp = (Meta_Data_Struct*)old_ptr - 1;
    Meta_Data_Struct* old_meta_data_pointer = tmp_oldp;

    int counter = 0;
    bool cond1 = (old_meta_data_pointer->md_next != nullptr);
    if (cond1)
    {
        Meta_Data_Struct* old_meta_data_pointer_next =old_meta_data_pointer->md_next;
        old_meta_data_pointer_next->md_prev = old_meta_data_pointer->md_prev;
        counter++;
    }

    bool cond2 = (old_meta_data_pointer->md_prev != nullptr);
    if (cond2)
    {
        Meta_Data_Struct* old_meta_data_pointer_prev =old_meta_data_pointer->md_prev;
        old_meta_data_pointer_prev->md_next = old_meta_data_pointer->md_next;
        counter++;
    }
    else
    {
        Meta_Data_Struct* old_meta_data_pointer_next = old_meta_data_pointer->md_next;
        list_of_mmap = old_meta_data_pointer_next;
        counter++;
    }

    size_t parameter_to_mmap_smalloc = param_size;
    void* new_pointer = mmap_smalloction(parameter_to_mmap_smalloc);
    size_t old_meta_data_pointer_size = old_meta_data_pointer->md_size;
    bool cond3 = (param_size < old_meta_data_pointer_size);
    if (cond3)
    {
        counter++;
        memmove(new_pointer, old_ptr, param_size);
    }
    else
    {
        /// cond3 ==0
        counter--;
        size_t old_meta_data_pointer_size = old_meta_data_pointer->md_size;
        memmove(new_pointer, old_ptr, old_meta_data_pointer_size);
    }
    size_t old_meta_data_pointer_size_PLUS_MD_SIZE = old_meta_data_pointer->md_size + METADATA_SIZE;
    munmap(old_ptr, old_meta_data_pointer_size_PLUS_MD_SIZE);
    return new_pointer;
}

void align_memory(size_t* size){
    *size += ((8 - (*size % 8)) % 8);
}
///functions

void* smalloc(size_t size) {
    align_memory(&size);
    bool cond1 =(size <= MINIMUM_SIZE);
    bool cond2 =(size > MAXIMUM_SIZE);
    if (cond1 || cond2)
        return nullptr;

    bool cond3 = (size >= LARGE_ALLOCATION);
    if (cond3){
        return mmap_smalloction(size);
    }
    if (list_of_memory_allocation != nullptr)
    {
        int bin_size = 128;
        for (int index = bin_Index(size); index < bin_size; index++)
        {
            Meta_Data_Struct* pMetaData = bins[index];
            while (pMetaData != nullptr)
            {
                size_t meta_data_size = pMetaData->md_size;
                if (meta_data_size >= size)
                {
                    pMetaData->md_is_free = false;
                    bin_Remove(pMetaData);
                    split_block_by_size(pMetaData, size);
                    return pMetaData + 1;
                }
                pMetaData = pMetaData->md_next_free;
            }
        }

        int block_counter = 0;
        Meta_Data_Struct* wild_chunk = list_of_memory_allocation;
        //todo: make sure this is the wild chunk
        while (wild_chunk->md_next)
        {
            wild_chunk = wild_chunk->md_next;
            block_counter++;
        }
        if (wild_chunk->md_is_free)
        {
            Meta_Data_Struct* block_before_wc = wild_chunk->md_prev;
            if (block_before_wc != nullptr && block_before_wc->md_is_free) ///merge down if we can
            {
                void* new_heap_pointer = sbrk(size - wild_chunk->md_size - block_before_wc->md_size - sizeof(Meta_Data_Struct));
                if (new_heap_pointer == (void*)(-1))
                    return nullptr;

                bin_Remove(block_before_wc);
                bin_Remove(wild_chunk);

                block_before_wc->md_is_free = false;
                wild_chunk->md_is_free = false;

                block_before_wc->md_next = nullptr;
                block_before_wc->md_size = size;

                return block_before_wc + 1;
            }
            ///
            /// in case we can't merge down
            ///

            void* new_heap_pointer = sbrk(size - wild_chunk->md_size);
            if (new_heap_pointer == (void*)(-1)) {
                return nullptr;
            }bin_Remove(wild_chunk);
            wild_chunk->md_is_free = false;
            wild_chunk->md_size = size;
            return wild_chunk + 1;
        }
    }

    int wanted_size = size + sizeof(Meta_Data_Struct);
    Meta_Data_Struct* new_meta_data = (Meta_Data_Struct*)sbrk(wanted_size);
    if (new_meta_data == (void*)(-1))
    {
        return nullptr;
    }

    new_meta_data->md_is_free = false;
    new_meta_data->md_size = size;
    new_meta_data->md_next = new_meta_data->md_prev = nullptr;

    if (list_of_memory_allocation == nullptr)
    {
        list_of_memory_allocation = new_meta_data;
    }
    else
    {
        int counter = 0;
        Meta_Data_Struct* final_md_in_list = list_of_memory_allocation;
        ///note: this pointer is not yet the last one
        ///      but we gonna make him the lsat one
        while (final_md_in_list->md_next)
        {
            counter++;
            final_md_in_list = final_md_in_list->md_next;
        }
        new_meta_data->md_prev = final_md_in_list;
        final_md_in_list->md_next = new_meta_data;
    }


    return new_meta_data + 1;
}



void* scalloc(size_t num, size_t size)
{
    size_t alloc_size = num * size;
    align_memory(&alloc_size);

    void* address_of_allocation = smalloc(alloc_size);

    if (address_of_allocation == nullptr) {//make sure the allocation did not fail
        return nullptr;
    }
    else {
        size_t godel = num * size;
        int wanted_size = 0;
        return memset(address_of_allocation, wanted_size, alloc_size);}
}

void sfree(void* p) {
    if (p == nullptr) {
        return; }
    Meta_Data_Struct* meta_data = (Meta_Data_Struct*)p - 1;

    bool cond1 = (meta_data->md_size < LARGE_ALLOCATION);


    if (meta_data->md_is_free) {
        return; }

    else if (cond1)
    {
        meta_data->md_is_free = true;
        bin_Insert(meta_data);
        merge_not_in_use(meta_data);
    }
    else
    {

        bool has_prev = meta_data->md_prev != nullptr;
        if (has_prev)
        {
            meta_data->md_prev->md_next = meta_data->md_next;
        }
        else
        {
            Meta_Data_Struct*next = meta_data->md_next;
            list_of_mmap = next;
        }
        bool has_next = meta_data->md_next != nullptr;
        if (has_next)
        {
            meta_data->md_next->md_prev = meta_data->md_prev;
        }
        size_t size_md = meta_data->md_size + METADATA_SIZE;
        munmap(p, size_md);
    }
}

void* srealloc(void* oldp, size_t size) {
    align_memory(&size);
    bool cond1 = (size <= MINIMUM_SIZE);
    bool cond2 = (size > MAXIMUM_SIZE);
    if (cond1 || cond2) {
        return nullptr;
    }

    bool oldP_is_null =(oldp == nullptr);
    if (oldP_is_null) {
        return smalloc(size); }

    bool valid_size =(size >= LARGE_ALLOCATION);
    if (valid_size) {
        return mmap_srealloction(oldp, size); }

    Meta_Data_Struct* old_meta_data = (Meta_Data_Struct*) oldp - 1;

    Meta_Data_Struct* after_meta_data = old_meta_data->md_next;
    Meta_Data_Struct* before_meta_data = old_meta_data->md_prev;

    bool before_meta_data_is_free = before_meta_data != nullptr && before_meta_data->md_is_free ;
    bool before_meta_data_has_enought_size = before_meta_data != nullptr && before_meta_data->md_size + old_meta_data->md_size + METADATA_SIZE >= size;

    bool after_meta_data_is_free = after_meta_data != nullptr && after_meta_data->md_is_free;
    bool after_meta_data_has_enought_size = after_meta_data != nullptr && after_meta_data->md_size + old_meta_data->md_size + METADATA_SIZE >= size;

    size_t size_of_old_md = old_meta_data->md_size;
    if (size_of_old_md >= size)
    {
        old_meta_data->md_is_free = false;
        ///has enough size so split
        split_block_by_size(old_meta_data, size);
        return oldp;
    }

    else if (before_meta_data_is_free && before_meta_data_has_enought_size)
    {
        bin_Remove(before_meta_data);
        before_meta_data->md_next = old_meta_data->md_next;
        if (old_meta_data->md_next != nullptr)
        {
            ///set prev of next if we can
            old_meta_data->md_next->md_prev = before_meta_data;
        }
        before_meta_data->md_is_free = false;
        before_meta_data->md_size += old_meta_data->md_size + METADATA_SIZE;

        memmove(before_meta_data + 1, oldp, old_meta_data->md_size); ///move the data to where we want
        split_block_by_size(before_meta_data, size);
        return before_meta_data + 1;
    }

    else if (after_meta_data_is_free && after_meta_data_has_enought_size)
    {
        bin_Remove(after_meta_data);
        old_meta_data->md_next = after_meta_data->md_next;
        if (after_meta_data->md_next != nullptr)
        {
            ///set prev of next if we can
            after_meta_data->md_next->md_prev = old_meta_data;
        }
        after_meta_data->md_is_free = false;
        old_meta_data->md_size += after_meta_data->md_size + METADATA_SIZE;

        split_block_by_size(old_meta_data, size);
        return old_meta_data + 1;
    }

    else if (before_meta_data_is_free && after_meta_data_is_free &&
             before_meta_data->md_size + old_meta_data->md_size + after_meta_data->md_size + 2*METADATA_SIZE >= size)
    {

        bin_Remove(after_meta_data);
        bin_Remove(before_meta_data);

        before_meta_data->md_next = after_meta_data->md_next;
        before_meta_data->md_is_free = after_meta_data->md_is_free = false;

        if (after_meta_data->md_next != nullptr)
        {
            after_meta_data->md_next->md_prev = before_meta_data;
        }
        before_meta_data->md_size += old_meta_data->md_size + after_meta_data->md_size + 2*METADATA_SIZE;

        memmove(before_meta_data + 1, oldp, old_meta_data->md_size);
        split_block_by_size(before_meta_data, size);
        return before_meta_data + 1;
    }

    else if (old_meta_data->md_next == nullptr) {
        if (before_meta_data != nullptr && before_meta_data->md_is_free){ ///merge down if we can
            void* enlarge = sbrk(size - old_meta_data->md_size - before_meta_data->md_size - sizeof(Meta_Data_Struct));
            if (enlarge == (void*)(-1))
                return nullptr;

            bin_Remove(before_meta_data);
            bin_Remove(old_meta_data);

            before_meta_data->md_is_free = false;
            old_meta_data->md_is_free = false;

            before_meta_data->md_next = nullptr;
            before_meta_data->md_size = size;

            memmove(before_meta_data + 1, oldp, old_meta_data->md_size);

            return before_meta_data + 1;
        }

        void* new_heap_pointer = sbrk(size - old_meta_data->md_size);
        if (new_heap_pointer == (void*)(-1)) {
            return nullptr;
        }

        old_meta_data->md_size = size;
        return old_meta_data + 1;
    }

    else
    {
        void* address_of_new_allocation = smalloc(size);
        if (address_of_new_allocation == nullptr) {
            return nullptr;}

        memmove(address_of_new_allocation, oldp, old_meta_data->md_size);
        bin_Insert(old_meta_data);
        old_meta_data->md_is_free = true;
        return address_of_new_allocation;
    }
}




size_t _num_free_blocks() {
    size_t block_counter = 0;
    int bin_size = 128;
    for (int ind = 0; ind < bin_size; ind++)
    {
        Meta_Data_Struct* meta_data = bins[ind];
        while (meta_data != nullptr)
        {
            meta_data = meta_data->md_next_free;
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
        Meta_Data_Struct* meta_data = bins[ind];
        while (meta_data != nullptr)
        {
            counter_of_free_bytes += meta_data->md_size;
            meta_data = meta_data->md_next_free;
        }
    }
    return counter_of_free_bytes;
}

size_t _num_allocated_blocks()
{
    size_t allocated_blocks_counter = 0;

    if (list_of_mmap != nullptr)
    {
        for (Meta_Data_Struct* meta_data = list_of_mmap; meta_data != nullptr; meta_data = meta_data->md_next)
        {
            allocated_blocks_counter++;
        }
    }
    if (list_of_memory_allocation != nullptr)
    {
        for (Meta_Data_Struct* meta_data = list_of_memory_allocation; meta_data != nullptr; meta_data = meta_data->md_next)
        {
            allocated_blocks_counter++;
        }
    }
    return allocated_blocks_counter;
}

size_t _num_allocated_bytes()
{
    size_t counter_of_allocated_bytes = 0;
    if (list_of_memory_allocation != nullptr)
    {
        for (Meta_Data_Struct* meta_data = list_of_memory_allocation; meta_data != nullptr; meta_data = meta_data->md_next)
        {
            counter_of_allocated_bytes += meta_data->md_size;
        }
    }
    if (list_of_mmap != nullptr)
    {
        for (Meta_Data_Struct* meta_data = list_of_mmap; meta_data != nullptr; meta_data = meta_data->md_next)
        {
            counter_of_allocated_bytes += meta_data->md_size;
        }
    }
    return counter_of_allocated_bytes;
}

size_t _size_meta_data()
{
    return sizeof(Meta_Data_Struct);
}

size_t _num_meta_data_bytes()
{
    return _num_allocated_blocks() * _size_meta_data();
}