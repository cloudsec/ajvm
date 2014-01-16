/*
 * slab.c - Slab Memory alloctor
 *
 * Copywrite (c) 2011, 2012, 2013 wzt	http://www.cloud-sec.org
 *
 * 
 *  -------     ------     ------    ------
 *  |cache|-->  |slab| --> |slab| -->|slab|
 *  -------     ------     ------    ------
 *  |cache|
 *  -----
 *  |cache| ... 
 *  -----      ------     ------    ------
 *  |cache|--> |slab| --> |slab| -->|slab|
 *  -----      ------     -----     ------
 *  |cache| ...
 *  -------    
 *  |cache|
 *  ------- 
 *  |cache|-->|slab|-->|slab| -->|slab|
 *  -------   ------   ------    ------
 *
 *
 * current support:
 *
 * - basic implement for slab alloctor.
 * - hardware cache support.
 * - slab expand support.
 * - genernal slab and slab cache support.
 *
 * todo:
 *
 * - slab obj cache support.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <pthread.h>

#include "list.h"
#include "slab.h"
#include "log.h"

static int slab_size[SLAB_SIZE_NUM] = {8, 16, 32, 64, 128, 256, 512, 1024, 2048};

void show_slab_info(struct slab *slab)
{
	debug2("obj num: %d\tfree_num: %d\tfree_idx: %d\tbase: 0x%016x\n",
		slab->obj_num, slab->free_num, 
		slab->free_idx, slab->base);
}

void __show_slab_list(struct list_head *list_head)
{
	struct slab *slab;
	struct list_head *p;

	if (list_empty(list_head))
		return ;

	list_for_each(p, list_head) {
		slab = list_entry(p, struct slab, list);
		if (slab)
			show_slab_info(slab);
	}
}

void show_slab_cache(struct slab_cache *slab_cache)
{
	debug2("slab size: %d slab num: %d obj_num: %d "
		"free num: %d color num: %d color next: %d\n",
		slab_cache->slab_size, 
		slab_cache->slab_num,
		slab_cache->obj_num,
		slab_cache->free_num,
		slab_cache->color_num,
		slab_cache->color_next);
}

void show_slab_list(struct thread_mem *thread_mem)
{
	int idx;

	for (idx = 0; idx < thread_mem->slab_cache_array_size; idx++) {
		debug2("slab size: %d slab num: %d free num: %d color num: %d\n",
			thread_mem->slab_cache_array[idx].slab_size, 
			thread_mem->slab_cache_array[idx].slab_num,
			thread_mem->slab_cache_array[idx].free_num,
			thread_mem->slab_cache_array[idx].color_num);
		__show_slab_list(&(thread_mem->slab_cache_array[idx].list));
	}
}

/* bufctl just behind the slab struct. */
unsigned int *slab_bufctl(struct slab *slab)
{
	return (unsigned int *)(slab + 1);
}

/* get an obj from a slab. */
void *get_slab_obj(struct slab *slab, struct slab_cache *slab_cache)
{
	void *obj;

	obj = slab->base + slab_cache->slab_size * slab->free_idx;

	slab->free_idx = slab_bufctl(slab)[slab->free_idx];

	slab->free_num--;
	slab_cache->free_num--;

	debug2("slab base: 0x%016x\tfree_idx: %d\t"
		"slab_free_num: %d\tslab_cache->free_num: %d\n", 
		slab->base, slab->free_idx,
		slab->free_num, slab_cache->free_num);
	debug2("alloc at 0x%016x ok.\n", obj);

	return obj;
}

void *get_obj_from_cache(struct slab_obj_cache *obj_cache)
{
	--obj_cache->curr_obj;

	return (void *)((unsigned int *)(obj_cache->entry) + obj_cache->curr_obj);
}

void set_slab_obj_cache(struct slab *slab, struct slab_cache *slab_cache)
{
	int idx;

	slab_cache->obj_cache->entry = 
			(void *)malloc(sizeof(int) * slab_cache->slab_num);
	if (!slab_cache->obj_cache->entry) {
		error("malloc failed.\n");
		exit(-1);
	}

	/* allocte obj from end to head. */
	slab_cache->obj_cache->curr_obj = slab->obj_num;
	slab_cache->obj_cache->limit = slab->obj_num;

	for (idx = 0; idx < slab->obj_num - 1; idx++) {
		*(((unsigned int *)slab_cache->obj_cache->entry + idx)) = 
			get_slab_obj(slab, slab_cache);
	}
	slab_cache->obj_cache->curr_obj = 0;
}

int check_slab_size(int size)
{
        int i;

        for (i = 0; i < SLAB_SIZE_NUM; i++) {
                if (size <= slab_size[i])
                        return i;
        }

        return -1;
}

/* 
 * expand a new slab with PAGE_SIZE. 
 */
void *expand_slab(struct slab_cache *slab_cache)
{
	void *new_slab = NULL;

	//new_slab = get_new_page(SLAB_MAX_ORDER, MEM_ALLOC_GLIBC);
	new_slab = get_new_page(SLAB_MAX_ORDER, MEM_ALLOC_MMAP);
	if (!new_slab) {
		error("alloc_page failed.\n");
		return NULL;
	}
	
	__init_slab(slab_cache, new_slab, slab_cache->slab_size);
	
	slab_cache->slab_num++;

	return new_slab;
}

void *slab_alloc(struct thread_mem *thread_mem, int size)
{
	struct slab_cache *slab_cache;
	struct slab *new_slab = NULL;
	struct list_head *p = NULL;
	int idx = -1;

	if (size < 8 || size > 2048)
		return malloc(size);

	idx = check_slab_size(size);
	if (idx == -1)
		return malloc(size);
	debug2("idx: %d\tsize: %d\n", idx, slab_size[idx]);

	slab_cache = thread_mem->slab_cache_array + idx;
	if (slab_cache->obj_cache->curr_obj != 0) {
		debug2("get obj from cache.\n");
		return get_obj_from_cache(slab_cache->obj_cache);
	}

	debug2("get obj from slab.\n");
	if (!slab_cache->free_num) {
		debug2("expand slab obj in size %d.\n", size);
		if (!(new_slab = expand_slab(slab_cache))) {
			debug2("expand slab failed.\n");
			return NULL;
		}
		debug2("expand slab obj in size %d ok.\n", size);
		return get_slab_obj(new_slab, slab_cache);
	}

	debug2("get obj from slab list.\n");
	list_for_each(p, (&(slab_cache->list))) {
		new_slab = list_entry(p, struct slab, list);
		if (new_slab && new_slab->free_num) {
			show_slab_cache(slab_cache);
			return get_slab_obj(new_slab, slab_cache);
		}
	}

	return NULL;
}

/*
 * support for slab_free & kmem_cache_free.
 */
struct slab *search_slab(void *addr, struct list_head *list_head)
{
	struct slab *slab;
	struct list_head *p;

	assert(list_head != NULL);

	list_for_each(p, list_head) {
		slab = list_entry(p, struct slab, list);
		if (slab) { 
			if (slab->base <= addr && 
				addr <= ((void *)slab + SLAB_MAX_SIZE))
				return slab;
		}
	}

	return NULL;
}

void *put_slab_obj(struct slab *slab, void *obj, struct slab_cache *slab_cache)
{
	int obj_idx;

	assert(slab != NULL && slab_cache != NULL);

	debug2("free obj: 0x%016x, slab->base: 0x%016x slab size: %d\n", 
		obj, slab->base, slab_cache->slab_size);

	obj_idx = (obj - slab->base) / slab_cache->slab_size;
	debug2("obj_idx: %d\n", obj_idx);
	
	slab_bufctl(slab)[obj_idx] = slab->free_idx;
	slab->free_idx = obj_idx;

	slab->free_num++;
	slab_cache->free_num++;
	debug2("free obj: 0x%016x, slab->base: 0x%016x slab size: %d\n", 
		obj, slab->base, slab_cache->slab_size);
}

int slab_free(struct thread_mem *thread_mem, void *addr, int size)
{
	struct slab *slab;
	int cache_idx;

	assert(thread_mem != NULL);

	if (!addr)
		return 0;

	cache_idx = check_slab_size(size);
	if (cache_idx < 0 || cache_idx >= SLAB_SIZE_NUM) {
		error("bad idx: %d\n", cache_idx);
		return -1;
	}

	slab = search_slab(addr, &(thread_mem->slab_cache_array[cache_idx].list));
	if (!slab) {
		error("search slab failed with addr: 0x%016\n", addr);
		return -1;
	}
	debug2("search slab %d with addr: 0x%016x ok.\n",  
		slab_size[cache_idx], addr);
		
	put_slab_obj(slab, addr, &(thread_mem->slab_cache_array[cache_idx]));
	debug2("free addr 0x%016x ok.\n", addr);

	return 0;
}

/*
 * compute per slab obj num.
 */
int compute_slab_obj_num(int obj_size, int slab_size)
{
	return (slab_size - sizeof(struct slab)) / (obj_size + sizeof(int));
}

/*
 * compute slab color num for hardware cache.
 */
int compute_slab_color_num(int obj_size, int slab_size)
{
	return (slab_size - sizeof(struct slab)) % (obj_size + sizeof(int));
}

int get_slab_color(struct slab_cache *slab_cache)
{
	if (slab_cache->color_next >= slab_cache->color_num) {
		slab_cache->color_next = 0;
		return 0;
	}
	else {
		return ++slab_cache->color_next;
	}
}

void *set_slab_base_addr(void *addr, struct slab *new_slab)
{
/*
	return (void *)(ALIGN((unsigned int)(addr + sizeof(struct slab) +
                (new_slab->obj_num * sizeof(int))), DEFAULT_ALIGN));
*/
	return (void *)(addr + sizeof(struct slab) + new_slab->obj_num * sizeof(int));
}

/* 
 * support for CPU hardware cache.
 */
void *fix_slab_base_addr(void *addr, int color)
{
	return (void *)(addr + color);
}

/* 
 * all the slab managment builtin the front of the slab, next is bufctl
 * array which is a sample link list of obj. the end of the slab maybe
 * not used, it can be used for slab color for hardware cache.
 *
 * the slab struct like this:
 *
 * +-----------------------------------------------+
 * | struct slab | bufctl | obj | obj | ...| color |
 * +-----------------------------------------------+
 * 
 */
int __init_slab(struct slab_cache *slab_cache, void *addr, int size)
{
	struct slab *new_slab = (struct slab *)addr;
	int idx;

	new_slab->obj_num = compute_slab_obj_num(size, SLAB_MAX_SIZE);
	slab_cache->obj_num += new_slab->obj_num;
	new_slab->free_num = new_slab->obj_num;
	debug2("slab obj_num: %d\n", new_slab->obj_num);

	for (idx = 0; idx < new_slab->obj_num - 1; idx++)
		slab_bufctl(new_slab)[idx] = idx + 1;
	slab_bufctl(new_slab)[idx] = -1;

        if (slab_cache->ctor)
                slab_cache->ctor();

        slab_cache->free_num += new_slab->free_num;
        slab_cache->color_next = get_slab_color(slab_cache);
	debug2("color num: %d\n", slab_cache->color_num);
	debug2("color next: %d\n", slab_cache->color_next);
	
	//set_slab_obj_cache(new_slab, slab_cache);

	new_slab->free_idx = 0;
	list_add_tail(&(new_slab->list), &(slab_cache->list));

	new_slab->base = set_slab_base_addr(addr, new_slab);	
	debug2("slab base: 0x%016x\n", new_slab->base);
	new_slab->base = fix_slab_base_addr(new_slab->base, 
					slab_cache->color_next);
	debug2("new slab base: 0x%016x\n", new_slab->base);
	return 0;
}

void *get_new_page(int order, int flag)
{
	void *mem = NULL;

	switch (flag) {
	case MEM_ALLOC_MMAP:
		mem = mmap(NULL, SLAB_MAX_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		break;
	case MEM_ALLOC_GLIBC:
		mem = malloc(PAGE_SIZE * (1 << order));
		break;
	default:
		return NULL;
	}

	return mem;
}

void *free_page(int flag, void *addr)
{
	switch (flag) {
	case MEM_ALLOC_MMAP:
		munmap(addr, SLAB_MAX_SIZE);
		break;
	case MEM_ALLOC_GLIBC:
		free(addr);
		break;
	default:
		return ;
	}

	return ;
}

int init_slab(struct slab_cache *slab_cache, int size)
{
	void *addr;

	//addr = get_new_page(SLAB_MAX_ORDER, MEM_ALLOC_GLIBC);
	addr = get_new_page(SLAB_MAX_ORDER, MEM_ALLOC_MMAP);
	if (!addr) {
		error("alloc page failed.\n");
		return -1;
	}

	if (__init_slab(slab_cache, addr, size) == -1) {
		error("init slab failed.\n");
		return -1;
	}

	debug2("init slab ok.\n");
	return 0;
}

int init_general_slab_cache(struct thread_mem *thread_mem)
{
	int idx;

	for (idx = 0; idx < thread_mem->slab_cache_array_size; idx++) {
		(thread_mem->slab_cache_array + idx)->obj_cache = 
			(struct slab_obj_cache *)malloc(sizeof(struct slab_obj_cache));
		if (!thread_mem->slab_cache_array[idx].obj_cache) {
			error("alloc obj cache failed.\n");
			goto out;
		}
		memset((thread_mem->slab_cache_array + idx)->obj_cache, '\0',
			sizeof(struct slab_obj_cache));
		thread_mem->slab_cache_array[idx].slab_size = slab_size[idx];
		thread_mem->slab_cache_array[idx].slab_num = 0;
		thread_mem->slab_cache_array[idx].obj_num = 0;
		thread_mem->slab_cache_array[idx].free_num = 0;
		thread_mem->slab_cache_array[idx].ctor = NULL;
		thread_mem->slab_cache_array[idx].dtor = NULL;
		thread_mem->slab_cache_array[idx].color_num = 
			compute_slab_color_num(slab_size[idx], SLAB_MAX_SIZE);
        	thread_mem->slab_cache_array[idx].color_next = -1;
		thread_mem->slab_cache_array[idx].thread = thread_mem;
		INIT_LIST_HEAD(&(thread_mem->slab_cache_array[idx].list));
		INIT_LIST_HEAD(&(thread_mem->slab_cache_array[idx].cache_list));
	}

	debug2("Init genernal slab cache ok.\n");
	return 0;

out:
	for (; idx > 0; idx--)
		free(thread_mem->slab_cache_array[idx].obj_cache);

	return -1;
}

void free_slab(struct slab_cache *slab_cache)
{
        struct slab *slab;
        struct list_head *p, *q;

        list_for_each_safe(p, q, (&(slab_cache->list))) {
                slab = list_entry(p, struct slab, list);
                if (slab) {
                        list_del(p);
                        //free_page(MEM_ALLOC_GLIBC, (void *)slab);
                        free_page(MEM_ALLOC_MMAP, (void *)slab);
                }
        }

}

void free_slab_cache(struct thread_mem *thread_mem)
{
        struct slab_cache *slab_cache;
        struct list_head *p, *q;

        list_for_each_safe(p, q, (&(thread_mem->kmem_list_head))) {
                slab_cache = list_entry(p, struct slab_cache, cache_list);
                if (slab_cache) {
                        list_del(p);
                        //free_page(MEM_ALLOC_GLIBC, (void *)slab_cache);
                        free_page(MEM_ALLOC_MMAP, (void *)slab_cache);
                }
        }
}

void destroy_general_slab_cache(struct thread_mem *thread_mem)
{
	int idx;

	for (idx = 0; idx < thread_mem->slab_cache_array_size; idx++) {
		free((thread_mem->slab_cache_array + idx)->obj_cache);
		free_slab(thread_mem->slab_cache_array + idx);
	}
}

void *kmem_cache_alloc(struct slab_cache *slab_cache)
{
	struct slab *s = NULL;
	struct list_head *p = NULL;
	void *obj = NULL;

	assert(slab_cache != NULL);

	if (!slab_cache->free_num) {
		if (!(s = expand_slab(slab_cache))) {
			error("expand slab failed.\n");
			return NULL;
		}
		debug2("expand slab ok.\n");
		obj = get_slab_obj(s, slab_cache);
		return obj;
	}

	if (list_empty(&(slab_cache->list))) {
		return NULL;
	}

	list_for_each(p, (&(slab_cache->list))) {
		s = list_entry(p, struct slab, list);
		if (s && s->free_num) {
			obj = get_slab_obj(s, slab_cache);
			return obj;
		}
	}

	return NULL;
}

struct slab_cache *search_slab_cache(struct thread_mem *thread_mem, char *name)
{
	struct slab_cache *s = NULL;
	struct list_head *p = NULL;

	list_for_each(p, (&(thread_mem->kmem_list_head))) {
		s = list_entry(p, struct slab_cache, cache_list);
		if (s && !strcmp(name, s->name))
			return s;
	}

	return NULL;
}

struct slab_cache *kmem_cache_create(struct thread_mem *thread_mem, 
		char *name, int size)
{
	struct slab_cache *cachep;

	assert(thread_mem != NULL);

	if (search_slab_cache(thread_mem, name)) {
		error("kmem_cache: %s already exist.\n", name);
		return NULL;
	}

	cachep = (struct slab_cache *)kmem_cache_alloc(thread_mem->kmem_cache_st);
	if (!cachep) {
		error("create kmem cache failed.\n");
		return NULL;
	}
	debug2("kmem cache alloc at 0x%016x\n", cachep);

	cachep->slab_size = ALIGN(size, DEFAULT_ALIGN);
	cachep->slab_num = SLAB_NUM;
	cachep->obj_num = 0;
	cachep->free_num = 0;
	cachep->ctor = NULL;
	cachep->dtor = NULL;
	cachep->thread = thread_mem;

	strcpy(cachep->name, name);

	INIT_LIST_HEAD(&(cachep->list));
	init_slab(cachep, cachep->slab_size);
	list_add_tail(&(cachep->cache_list), &(thread_mem->kmem_list_head));

	return cachep;
}

int kmem_cache_free(struct slab_cache *slab_cache, void *addr)
{
	struct slab *slab = NULL;
	
	if (!slab_cache || !addr)
		return -1;

	slab = search_slab(addr, (&(slab_cache->list)));
	if (!slab) {
		error("not found slab: %s\n", slab_cache->name);
		return -1;
	}
	debug2("found slab: %s\n", slab_cache->name);

	put_slab_obj(slab, addr, slab_cache);

	return 0;
}

void kmem_cache_destroy(struct thread_mem *thread_mem, struct slab_cache *slab_cache)
{
	free_slab(slab_cache);
	//free_page(MEM_ALLOC_GLIBC, (void *)slab_cache->obj_cache);
	free_page(MEM_ALLOC_MMAP, (void *)slab_cache->obj_cache);
	kmem_cache_free(thread_mem->kmem_cache_st, (void *)slab_cache);
}

void kmem_cache_list_destroy(struct thread_mem *thread_mem)
{
	struct slab_cache *slab_cache;
	struct list_head *p, *q;

	list_for_each_safe(p, q, (&(thread_mem->kmem_list_head))) {
		slab_cache = list_entry(p, struct slab_cache, cache_list);
		if (slab_cache) {
			if (!strcmp(slab_cache->name, "kmem_cache_st"))
				continue;
			debug2("destroy kmem cache: %s\n", slab_cache->name);
			list_del(p);
			free_slab(slab_cache);
			//free_page(MEM_ALLOC_GLIBC, (void *)slab_cache->obj_cache);
			free_page(MEM_ALLOC_MMAP, (void *)slab_cache->obj_cache);
		}
	}

	free_slab(thread_mem->kmem_cache_st);
}

void print_kmem_cache_list(struct thread_mem *thread_mem)
{
	struct slab_cache *s = NULL;
	struct list_head *p = NULL;

	list_for_each(p, (&(thread_mem->kmem_list_head))) {
		s = list_entry(p, struct slab_cache, cache_list);
		if (s) {
			debug2("cache name: %s slab size: %d slab num: %d "
				"free num: %d color num: %d\n",
				s->name, s->slab_size, s->slab_num, 
				s->free_num, s->color_num); 
			__show_slab_list(&(s->list));
		}
	}
}

int init_kmem_cache(struct thread_mem *thread_mem)
{
	thread_mem->kmem_cache_st->slab_size = SLAB_CACHE_SIZE;
	thread_mem->kmem_cache_st->slab_num = SLAB_NUM;
	thread_mem->kmem_cache_st->free_num = 0;
	thread_mem->kmem_cache_st->obj_num = 0;
	thread_mem->kmem_cache_st->color_num = 
			compute_slab_color_num(SLAB_CACHE_SIZE, SLAB_MAX_SIZE);
	thread_mem->kmem_cache_st->ctor = NULL;
	thread_mem->kmem_cache_st->dtor = NULL;
	thread_mem->kmem_cache_st->thread = thread_mem;

	strcpy(thread_mem->kmem_cache_st->name, "kmem_cache_st");

	INIT_LIST_HEAD(&(thread_mem->kmem_cache_st->list));
	list_add_tail(&(thread_mem->kmem_cache_st->cache_list), 
			&(thread_mem->kmem_list_head));

	if (init_slab(thread_mem->kmem_cache_st, SLAB_CACHE_SIZE) == -1) {
		error("init slab failed.\n");
		return -1;
	}

	debug2("Init kmem cache ok.\n");
	return 0;
}

struct thread_mem *mem_cache_init(int array_size)
{
	struct thread_mem *thread_mem = NULL;

	thread_mem = (struct thread_mem *)malloc(sizeof(struct thread_mem));
	if (!thread_mem) {
		error("Malloc failed.\n");
		return NULL;
	}
	thread_mem->slab_cache_array_size = array_size;

	thread_mem->slab_cache_array = (struct slab_cache *)
			malloc(sizeof(struct slab_cache) * array_size);
	if (!thread_mem->slab_cache_array) {
		error("Malloc failed.\n");
		goto out_thread_mem;
	}
	
	thread_mem->kmem_cache_st = (struct slab_cache *)malloc(sizeof(struct slab_cache));
	if (!thread_mem->kmem_cache_st) {
		error("Malloc failed.\n");
		goto out_thread_mem;
	}

	INIT_LIST_HEAD(&(thread_mem->kmem_list_head));
	INIT_LIST_HEAD(&thread_mem_list_head);

	pthread_mutex_init(&(thread_mem->slab_lock), NULL);
	list_add_tail(&(thread_mem->list), &thread_mem_list_head);

	if (init_general_slab_cache(thread_mem) == -1)
		goto out_thread_mem;

	if (init_kmem_cache(thread_mem) == -1)
		goto out_thread_mem;

	return thread_mem;

out_thread_mem:
	free(thread_mem->kmem_cache_st);
	free(thread_mem->slab_cache_array);
	free(thread_mem);
	
	return NULL;
}

void mem_cache_destroy(struct thread_mem *thread_mem)
{
	destroy_general_slab_cache(thread_mem);
	free(thread_mem);
}
