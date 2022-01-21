#include <unistd.h>
#include <stdio.h>
#include <cstring>
#include <iostream>

#define MAX_BLOCK_SIZE 100000000

class MallocMetadata {
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
    void *address;

    // constructor for empty list
    MallocMetadata(size_t size, void *addr):size(size), is_free(false), address(addr)
    {
        this->next= nullptr;
        this->prev= nullptr;
    }

    // constructor for nonempty
    MallocMetadata(size_t size, void *addr, MallocMetadata *prev) :
    size(size), is_free(false), address(addr) {
        this->prev=prev;
        this->next=next;
    }
    //so we can use its private staff in list
    friend class List;
};


class List {
    MallocMetadata *head = nullptr;
    MallocMetadata *tail = nullptr;

    void new_tail_to_list(MallocMetadata *_ntail) {
        _ntail->prev = tail;
        tail = _ntail;
        tail->prev->next = tail;
        tail->next = nullptr;
    }

public:
    List() : head(nullptr), tail(nullptr) {}
    void *inset_to_mem_allocation_list(size_t size)
    {
        //case empty list
        if (head == nullptr)
        {
            // insert list head
            MallocMetadata *_nhead = (MallocMetadata *) sbrk(sizeof(MallocMetadata));
            if (_nhead == (void *) (-1))
            {
                return nullptr;
            }
            else
            {
                void *addr = sbrk(size);
                if (addr == (void *) (-1))
                {
                    return nullptr;
                }
                _nhead->size = size;
                _nhead->is_free = false;
                _nhead->address = addr;
                _nhead->prev = nullptr;
                _nhead->next = nullptr;
                head = _nhead;
                tail = _nhead;
                return addr;
            }
        }
        else
        {
            // like a queue add in the end
            MallocMetadata *_ntail = (MallocMetadata *) sbrk(sizeof(MallocMetadata));
            if (_ntail == (void *) (-1))
            {
                return nullptr;
            }
            else
            {
                void *addr = sbrk(size);
                if (addr == (void *) (-1))
                {
                    return nullptr;
                }
                _ntail->size = size;
                _ntail->is_free = false;
                _ntail->address = addr;
                new_tail_to_list(_ntail);
                return addr;
            }
        }
    }

    void mem_alloc_list_set_block_to_free_by_address(void *addr)
    {
        /// function called from functions:
        /// number 3 -> sfree, number 4-> srealloc
        /// Releases the usage of the block that starts with the pointer ‘p’
        if (head == nullptr)
        {
            return;
        }
        MallocMetadata *current_block = head;
        while (current_block)
        {
            ///  Releases the usage of the block that starts with the pointer ‘p’
            /// so need to check !curr->is_free
            if (current_block->address == addr && !current_block->is_free) {
                current_block->is_free = true;
                return;
            }
            current_block = current_block->next;
        }
    }

    void *mem_alloc_list_get_address_of_block_by_size(size_t size)
    {
        /// called from function number 1 -> smalloc
        if (head == nullptr)
        {
            // the list is empty, no free blocks
            return nullptr;
        }
        MallocMetadata *current_block = head;
        while (current_block)
        {
            if (current_block->is_free && current_block->size >= size)
            {
                current_block->is_free = false;
                return current_block->address;
            }
            current_block = current_block->next;
        }
        // not found free block have to allocate
        return nullptr;
    }

    size_t mem_alloc_list_get_block_size_by_address(void *addr)
    {
        /// used in function number 4 -> srealloc
        if (head == nullptr)
        {
            return 0;
        }
        MallocMetadata *current_block = head;
        while (current_block)
        {
            if (current_block->address == addr)
            {
                return current_block->size;
            }
            current_block = current_block->next;
        }
        return 0;
    }


    size_t mem_alloc_list_get_number_of_free_blocks()
    {
        /// called from function number 5 -> _num_free_blocks
        size_t number_of_free_blocks_counter = 0;
        MallocMetadata *current_block = head;
        while (current_block)
        {
            if (current_block->is_free)
            {
                number_of_free_blocks_counter++;
            }
            current_block = current_block->next;
        }
        return number_of_free_blocks_counter;
    }

    size_t mem_alloc_list_get_num_free_bytes()
    {
        /// called from function number 6 -> _num_free_bytes
        size_t num_free_bytes_counter = 0;
        MallocMetadata *current_block = head;
        while (current_block)
        {
            if (current_block->is_free)
            {
                num_free_bytes_counter += current_block->size;
            }
            current_block = current_block->next;
        }
        return num_free_bytes_counter;
    }

    size_t mem_alloc_list_get_num_allocated_blocks()
    {
        /// called from function number 7 -> _num_allocated_blocks
        size_t num_allocated_blocks_counter = 0;
        MallocMetadata *current_block = head;
        while (current_block)
        {
            num_allocated_blocks_counter++;
            current_block = current_block->next;
        }
        return num_allocated_blocks_counter;
    }

    size_t mem_alloc_list_get_num_allocated_bytes()
    {
        /// called from function number 8 -> _num_allocated_bytes
        size_t num_allocated_bytes = 0;
        MallocMetadata *current_block = head;
        while (current_block) {
            num_allocated_bytes += current_block->size;
            current_block = current_block->next;
        }
        return num_allocated_bytes;
    }

    size_t mem_alloc_list_get_metadata_size()
    {
        /// called from function number 10 -> _size_meta_data
        return sizeof(MallocMetadata);
    }
    size_t mem_alloc_list_get_num_metadata_bytes()
    {
        /// called from function number 9 -> _num_meta_data_bytes
        return mem_alloc_list_get_num_allocated_blocks() * mem_alloc_list_get_metadata_size();
    }

};

List *malloc_memory_allocation_block_list = (List *) sbrk(sizeof(List));

/// #smalloc
void *smalloc(size_t size)
{
    if (size == 0 || size > MAX_BLOCK_SIZE)
    {
        return nullptr;
    }
    /// Searches for a free block with up to ‘size’ bytes
    void *address = malloc_memory_allocation_block_list->mem_alloc_list_get_address_of_block_by_size(size);
    if (address != nullptr)
    {
        return address;
    }

    /// allocates (sbrk()) one if none are found.
    void *insert_result = malloc_memory_allocation_block_list->inset_to_mem_allocation_list(size);
    if (insert_result == nullptr)
    {
        return nullptr;
    }
    return insert_result;
}

/// #scalloc
void *scalloc(size_t num, size_t size)
{
    size_t new_size = num * size;

    /// Searches for a free block of up to ‘num’ elements
    void *address = smalloc(new_size);

    if (address == nullptr)
    {
        return nullptr;
    }
    // set blocks to 0
    int zero = 0;
    memset(address, zero, new_size);
    return address;
}

/// #sfree
void sfree(void *p)
{
    /// If ‘p’ is NULL or already released, simply returns.
    if (p == nullptr) {
        return;
    }
    malloc_memory_allocation_block_list->mem_alloc_list_set_block_to_free_by_address(p);
}

///#sreaalloc
void *srealloc(void *oldp, size_t size)
{
    if (size == 0 || size > MAX_BLOCK_SIZE)
    {
        return nullptr;
    }

    /// If ‘oldp’ is NULL, allocates space for ‘size’ bytes and returns a pointer to it.
    if (oldp == nullptr)
    {
        // there isn't previous address allocate a new by size
        return smalloc(size);
    }

    /// If ‘size’ is smaller than the current block’s size, reuses the same block
    size_t new_size = malloc_memory_allocation_block_list->mem_alloc_list_get_block_size_by_address(oldp);
    if (new_size >= size)
    {
        // block size match
        return oldp;
    }

    /// Otherwise, finds/allocates ‘size’ bytes for a new space, copies content of oldp into the new
    /// allocated space and frees the oldp.
    void *address_from_smalloc = smalloc(size);
    if (address_from_smalloc == nullptr)
    {
        return nullptr;
    }

    memmove(address_from_smalloc, oldp, new_size);
    malloc_memory_allocation_block_list->mem_alloc_list_set_block_to_free_by_address(oldp);
    return address_from_smalloc;
}

/// Returns the number of allocated blocks in the heap that are currently free
size_t _num_free_blocks() {
    return malloc_memory_allocation_block_list->mem_alloc_list_get_number_of_free_blocks();
}

/// Returns the number of bytes in all allocated blocks in the heap that are currently free,
/// excluding the bytes used by the meta-data structs.
size_t _num_free_bytes() {
    return malloc_memory_allocation_block_list->mem_alloc_list_get_num_free_bytes();
}

/// Returns the overall (free and used) number of allocated blocks in the heap.
size_t _num_allocated_blocks() {
    return malloc_memory_allocation_block_list->mem_alloc_list_get_num_allocated_blocks();
}

/// Returns the overall number (free and used) of allocated bytes in the heap, excluding
/// the bytes used by the meta-data structs.
size_t _num_allocated_bytes() {
    return malloc_memory_allocation_block_list->mem_alloc_list_get_num_allocated_bytes();
}

/// Returns the overall number of meta-data bytes currently in the heap.
size_t _num_meta_data_bytes() {
    return malloc_memory_allocation_block_list->mem_alloc_list_get_num_metadata_bytes();
}

// Returns the number of bytes of a single meta-data structure in your system.
size_t _size_meta_data() {
    return malloc_memory_allocation_block_list->mem_alloc_list_get_metadata_size();
}