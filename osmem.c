// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"

#define MMAP_THRESHOLD (128 * 1024)
#define PAGE_SIZE (4 * 1024)

size_t allign(size_t size)
{
	size_t div = size / 8;

	if (size % 8 != 0)
		size = (div + 1) * 8;
	return size;
}

void add_to_list(struct block_meta *addr)
{
	struct block_meta *curr = init;

	if (init == NULL) {
		init = addr;
	} else {
		while (curr->next != NULL)
			curr = curr->next;
		curr->next = addr;
	}
}

void add_to_list_heap(struct block_meta *addr)
{
	struct block_meta *curr = init;

	if (init == NULL) {
		init = addr;
	} else {
		while (curr->next != NULL && curr->next->status != STATUS_MAPPED)
			curr = curr->next;
		addr->next = curr->next;
		curr->next = addr;
	}
}

void delete_from_list(struct block_meta *block)
{
	struct block_meta *curr = init;

	while (curr->next != block)
		curr = curr->next;
	curr->next = block->next;
}

void initialize_struct(size_t size, int status, struct block_meta *addr)
{
	addr->size = size;
	addr->next = NULL;
	addr->status = status;

}

struct block_meta *find_best_fit(size_t size)
{
	struct block_meta *curr = init;
	struct block_meta *best_fit_block = NULL;

	while (curr != NULL) {
		if (curr->status == STATUS_FREE && curr->size >= size) {
			if (best_fit_block == NULL || curr->size < best_fit_block->size)
				best_fit_block = curr;
		}
		curr = curr->next;
	}

	return best_fit_block;
}

void split(struct block_meta *best_fit_block, size_t size)
{
	size_t remainder_size = best_fit_block->size - size;

	if (remainder_size > sizeof(struct block_meta)) {
		struct block_meta *new_block = (struct block_meta *)((char *)best_fit_block + sizeof(struct block_meta) + size);

		new_block->size = remainder_size - sizeof(struct block_meta);
		new_block->status = STATUS_FREE;
		new_block->next = best_fit_block->next;
		best_fit_block->next = new_block;
		best_fit_block->size = size;
	}
}

void *expand(size_t size)
{
	struct block_meta *curr = init;
	// expand block
	while (curr->next != NULL && curr->next->status != STATUS_MAPPED)
		curr = curr->next;

	if (curr->status == STATUS_FREE) {
		void *addr = sbrk(size - curr->size);

		DIE((intptr_t)addr == -1, "Eroare la sbrk");

		curr->size = size;
		curr->status = STATUS_ALLOC;
		return (void *)((char *)curr + sizeof(struct block_meta));
	}
	return NULL;
}

void *expand_realloc(size_t size, struct block_meta *curr)
{
	if (final_heap != NULL) {
		void *addr = sbrk(size - curr->size);

		DIE((intptr_t)addr == -1, "Eroare la sbrk");
		curr->size = size;
		curr->status = STATUS_ALLOC;
		return (void *)((char *)curr + sizeof(struct block_meta));
	}
	return NULL;
}

void split_bl(struct block_meta *block, size_t size, size_t new_size)
{
	struct block_meta *next_block = (struct block_meta *)((char *) block + size + sizeof(struct block_meta));

	next_block->next = block->next;
	block->next = next_block;
	next_block->status = STATUS_FREE;
	block->size = size;
	next_block->size = new_size;
}

void *malloc_implementation(size_t size, size_t comparison)
{
	if (size <= 0)
		return NULL;
	size = allign(size);
	// mmap alloc
	if (size + sizeof(struct block_meta) >= comparison) {
		struct block_meta *addr = mmap(NULL, size + sizeof(struct block_meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

		initialize_struct(size, STATUS_MAPPED, addr);
		add_to_list(addr);
		return (void *)((char *) addr + sizeof(struct block_meta));
	// heap alloc
	} else {
		if (final_heap == NULL) {
			char *start_heap = sbrk(0);

			DIE((intptr_t)start_heap == -1, "Eroare la sbrk");
			final_heap = start_heap + MMAP_THRESHOLD;
			int addr = brk(final_heap);

			DIE(addr == -1, "Eroare la brk");
			struct block_meta *block = (struct block_meta *)start_heap;

			initialize_struct(MMAP_THRESHOLD, STATUS_ALLOC, block);
			block->next = init;
			init = block;
			if (MMAP_THRESHOLD - size - sizeof(struct block_meta) > sizeof(struct block_meta)) {
				size_t new_size = MMAP_THRESHOLD - size - 2 * sizeof(struct block_meta);

				split_bl(block, size, new_size);
			}
			return (void *)((char *)block + sizeof(struct block_meta));
		}
		// Try to find a free block in the heap
		struct block_meta *best_fit_block = find_best_fit(size);

		if (best_fit_block != NULL) {
			// Split the block if there is space left
			split(best_fit_block, size);
			best_fit_block->status = STATUS_ALLOC;
			return (void *)((char *)best_fit_block + sizeof(struct block_meta));
		}
		// Allocate a new block
		void *ret = expand(size);

		if (ret == NULL) {
			struct block_meta *block = (struct block_meta *)sbrk(size + sizeof(struct block_meta));

			DIE((intptr_t)block == -1, "Eroare la sbrk");
			final_heap = block;
			initialize_struct(size, STATUS_ALLOC, block);
			// Update the linked list of blocks
			if (init == NULL) {
				block->next = init;
				init = block;
			} else {
				add_to_list_heap(block);
			}
			return (void *)((char *)block + sizeof(struct block_meta));
		}
		return ret;
	}
	return NULL;
}

void *os_malloc(size_t size)
{
	return malloc_implementation(size, MMAP_THRESHOLD);
}

void combine_blocks(struct block_meta *curr)
{
	struct block_meta *next_block = curr->next;

	curr->size += sizeof(struct block_meta) + next_block->size;
	curr->next = next_block->next;
}

void coalesce(void)
{
	struct block_meta *curr = init;

	// expand block
	while (curr != NULL && curr->next != NULL) {
		if (curr->status == STATUS_FREE && curr->next->status == STATUS_FREE)
			combine_blocks(curr);
		else
			curr = curr->next;
	}
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	struct block_meta *block = (struct block_meta *)((char *)ptr - sizeof(struct block_meta));
	size_t size = block->size;

	if (block->status == STATUS_MAPPED) {
		if (block == init)
			init = block->next;
		else
			delete_from_list(block);
		munmap((void *)block, size + sizeof(struct block_meta));
	} else {
		block->status = STATUS_FREE;
		coalesce();
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t total_size = nmemb * size;

	if (nmemb == 0 || size == 0)
		return NULL;
	void *ptr = malloc_implementation(total_size, PAGE_SIZE);

	if (ptr == NULL)
		return NULL;
	memset(ptr, 0, total_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	size = allign(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	if (ptr == NULL) {
		void *new_ptr = malloc_implementation(size, MMAP_THRESHOLD);

		return new_ptr;
	}
	struct block_meta *block = (struct block_meta *)((char *)ptr - sizeof(struct block_meta));
	size_t old_size = block->size;

	if (block->status == STATUS_FREE)
		return NULL;
	// if the memory can be put in the previous allocated
	if (size <= old_size) {
		if (block->status == STATUS_MAPPED) {
			void *new_ptr = malloc_implementation(size, MMAP_THRESHOLD);

			memcpy(new_ptr, ptr, size);
			os_free(ptr);
			return new_ptr;
		}
		if (size + sizeof(struct block_meta) < old_size) {
			size_t new_size = old_size - size - sizeof(struct block_meta);

			split_bl(block, size, new_size);
		}
		return ptr;
	}

	if (size < MMAP_THRESHOLD && (block->next == NULL || block->next->status == STATUS_MAPPED)) {
		void *ret =  expand_realloc(size, block);

		if (ret != NULL)
			return ret;
	}

	//Try to expand the block if possible
	if (block->next != NULL && block->next->status == STATUS_FREE) {
		// Coalesce the blocks
		coalesce();
		if (old_size + sizeof(struct block_meta) + block->next->size >= size) {
			struct block_meta *free_block = block->next;
			size_t free_size = free_block->size;

			block->next = free_block->next;
			if (old_size + sizeof(struct block_meta) + free_size - size > sizeof(struct block_meta)) {
				size_t new_size = old_size + free_size - size;

				split_bl(block, size, new_size);
			} else
				block->size = old_size + sizeof(struct block_meta) + free_size;
			return ptr;
		}
	}

	void *new_ptr = malloc_implementation(size, MMAP_THRESHOLD);

	memcpy(new_ptr, ptr, old_size);
	os_free(ptr);
	return new_ptr;
}
