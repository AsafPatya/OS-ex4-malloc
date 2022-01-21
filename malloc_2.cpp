
#include <unistd.h>
#include <stdio.h>
#include <cstring>
#include <iostream>

#define MAX_BLOCK_SIZE 100000000

class MallocMetadata {
    size_t size;
    bool is_free;
    void *address;
    MallocMetadata *next;
    MallocMetadata *prev;
    // constractor for empty list
    MallocMetadata(size_t size, void *addr) :
    size(size), is_free(false), address(addr) {
        this->next= nullptr;
        this->prev= nullptr;
    }
    // constractor for nonempty
    MallocMetadata(size_t size, void *addr, MallocMetadata *prev) :
    size(size), is_free(false), address(addr) {
        this->prev=prev;
        this->next=next;
    }
    //so we can use its privete staff in list
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
    //ctor
    List() : head(nullptr), tail(nullptr) {}
    void *Insert(size_t size) {
        //case empty list
        if (head == nullptr) {
            // insert list head
            MallocMetadata *_nhead = (MallocMetadata *) sbrk(sizeof(MallocMetadata));
            if (_nhead == (void *) (-1)) {
                return nullptr;
            }
            else {
                void *addr = sbrk(size);
                if (addr == (void *) (-1)) {
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
        } else {
            // like a queue add in the end
            MallocMetadata *_ntail = (MallocMetadata *) sbrk(sizeof(MallocMetadata));
            if (_ntail == (void *) (-1)) {
                return nullptr;
            } else {
                void *addr = sbrk(size);
                if (addr == (void *) (-1)) {
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

    void set_free_block(void *addr) {
        if (head == nullptr) {
            return;
        }
        MallocMetadata *curr = head;
        while (curr) {
            if (curr->address == addr && !curr->is_free) {
                curr->is_free = true;
                return;
            }
            curr = curr->next;
        }
    }

    void *get_addr_of_block_by_size(size_t size) {
        if (head == nullptr) {
            // the list is empty, no free blocks
            return nullptr;
        }
        MallocMetadata *curr = head;
        while (curr) {
            if (curr->is_free && curr->size >= size) {
                curr->is_free = false;
                return curr->address;
            }
            curr = curr->next;
        }
        // not found free block have to allocate
        return nullptr;
    }

    size_t get_block_size_by_addr(void *addr) {
        if (head == nullptr) {
            return 0;
        }
        MallocMetadata *curr = head;
        while (curr) {
            if (curr->address == addr) {
                return curr->size;
            }
            curr = curr->next;
        }
        return 0;
    }

    size_t get_num_free_bytes() {
        size_t sum = 0;
        MallocMetadata *curr = head;
        while (curr) {
            if (curr->is_free) {
                sum += curr->size;
            }
            curr = curr->next;
        }
        return sum;
    }

    size_t get_num_free_blocks() {
        size_t count = 0;
        MallocMetadata *curr = head;
        while (curr) {
            if (curr->is_free) {
                count++;
            }
            curr = curr->next;
        }
        return count;
    }
    size_t get_num_allocated_bytes() {
        size_t sum = 0;
        MallocMetadata *curr = head;
        while (curr) {
            sum += curr->size;
            curr = curr->next;
        }
        return sum;
    }
    size_t get_num_allocated_blocks() {
        size_t counter = 0;
        MallocMetadata *curr = head;
        while (curr) {
            counter++;
            curr = curr->next;
        }
        return counter;
    }
    size_t get_metadata_size() {
        return sizeof(MallocMetadata);
    }
    size_t get_num_metadata_bytes() {
        return get_num_allocated_blocks() * get_metadata_size();
    }

};

List *malloc_block_list = (List *) sbrk(sizeof(List));

void *smalloc(size_t size) {
    if (size == 0 || size > MAX_BLOCK_SIZE) {
        return nullptr;
    }
    void *_naddr = malloc_block_list->get_addr_of_block_by_size(size);
    if (_naddr != nullptr) {
        return _naddr;
    }
    // There's no free block according to the size given have to allocate
    void *ans = malloc_block_list->Insert(size);
    if (ans == nullptr) {
        return nullptr;
    }
    return ans;
}

void *scalloc(size_t num, size_t size) {
    size_t _nsize=num*size;
    void *addr = smalloc(_nsize);
    if (addr == nullptr) {
        return nullptr;
    }
    // set blocks to 0
    memset(addr, 0, _nsize);
    return addr;
}

void sfree(void *p) {
    if (p == nullptr) {
        return;
    }
    malloc_block_list->set_free_block(p);
}

void *srealloc(void *oldp, size_t size) {
    if (size == 0 || size > MAX_BLOCK_SIZE) {
        return nullptr;
    }
    if (oldp == nullptr) {
        // there isnt previous address allocate a new by size
        return smalloc(size);
    }
    size_t _nsize = malloc_block_list->get_block_size_by_addr(oldp);
    if (_nsize >= size) {
        // block size match
        return oldp;
    }
    void *_naddr = smalloc(size);
    if (_naddr == nullptr) {
        return nullptr;
    }
    memmove(_naddr, oldp, _nsize);
    malloc_block_list->set_free_block(oldp);
    return _naddr;
}
// Returns the number of allocated blocks in the heap that are currently free
size_t _num_free_blocks() {
    return malloc_block_list->get_num_free_blocks();
}

// Returns the number of bytes in all allocated blocks in the heap that are currently free,
// excluding the bytes used by the meta-data structs.
size_t _num_free_bytes() {
    return malloc_block_list->get_num_free_bytes();
}

// Returns the overall (free and used) number of allocated blocks in the heap.
size_t _num_allocated_blocks() {
    return malloc_block_list->get_num_allocated_blocks();
}

// Returns the overall number (free and used) of allocated bytes in the heap, excluding
// the bytes used by the meta-data structs.
size_t _num_allocated_bytes() {
    return malloc_block_list->get_num_allocated_bytes();
}

// Returns the overall number of meta-data bytes currently in the heap.
size_t _num_meta_data_bytes() {
    return malloc_block_list->get_num_metadata_bytes();
}

// Returns the number of bytes of a single meta-data structure in your system.
size_t _size_meta_data() {
    return malloc_block_list->get_metadata_size();
}