#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/epoll.h>

#include "list.h"
#include "slab.h"
#include "trace.h"
#include "log.h"

#define OBJ_NUM			2
#define OBJ_SIZE		32

struct thread_mem *main_thread_mem;

int slab_test(void)
{
	void **addr;
	int i;

	addr = (void **)malloc(OBJ_NUM * sizeof(long));

	main_thread_mem = mem_cache_init(SLAB_SIZE_NUM);
	assert(main_thread_mem != NULL);

	for (i = 0; i < OBJ_NUM; i++) {
		addr[i] = slab_alloc(main_thread_mem, OBJ_SIZE);
		assert (addr[i] != NULL);

		memset(addr[i], 'A', OBJ_SIZE);
		printf("[%5d] %s\n", i, addr[i]);
	}

	for (i = 0; i < OBJ_NUM; i++) {
		slab_free(main_thread_mem, addr[i], OBJ_SIZE);
	}

	for (i = 0; i < 2; i++) {
		addr[i] = slab_alloc(main_thread_mem, OBJ_SIZE);
		assert (addr[i] != NULL);

		memset(addr[i], 'A', OBJ_SIZE);
		printf("[%5d] %s\n", i, addr[i]);
	}
}

int slab_test1(void)
{
	void *addr;
	int i;

	main_thread_mem = mem_cache_init(SLAB_SIZE_NUM);
	assert(main_thread_mem != NULL);

	for (i = 0; i < 2; i++) {
		addr = slab_alloc(main_thread_mem, OBJ_SIZE);
		assert (addr != NULL);

		strcpy(addr, "hello, slab.");
		printf("%s\n", addr);
	}

	slab_free(main_thread_mem, addr, OBJ_SIZE);

	addr = slab_alloc(main_thread_mem, OBJ_SIZE);
	assert (addr != NULL);

	strcpy(addr, "hello, slab.");
	printf("%s\n", addr);
}

int slab_vs_glibc(int flag)
{
        void **addr;
	struct timeval sval, eval;
        int i;

        main_thread_mem = mem_cache_init(SLAB_SIZE_NUM);
        assert(main_thread_mem != NULL);

	addr = (void **)malloc(OBJ_NUM * sizeof(long));

	gettimeofday(&sval, NULL);
        for (i = 0; i < OBJ_NUM; i++) {
		if (flag)
                	addr[i] = slab_alloc(main_thread_mem, OBJ_SIZE);
		else
                	addr[i] = malloc(OBJ_SIZE);

                strcpy(addr[i], "hello, slab.");
                //printf("[%5d] %s\n", i, addr[i]);
        }

	gettimeofday(&eval, NULL);

	printf("%d:%d\t%d:%d\n", sval.tv_sec, sval.tv_usec,
				eval.tv_sec, eval.tv_usec);
	printf("%d\n", eval.tv_usec - sval.tv_usec);
	mem_cache_destroy(main_thread_mem);
}

void kmem_cache_test(void)
{
	struct slab_cache *sock;
	struct timeval sval, eval;
        void **addr;
	int i;

	addr = (void **)malloc(OBJ_NUM * sizeof(long));

        main_thread_mem = mem_cache_init(SLAB_SIZE_NUM);
        assert(main_thread_mem != NULL);

	sock = kmem_cache_create(main_thread_mem, "sock", 32);
	assert (sock != NULL);

	//gettimeofday(&sval, NULL);
        for (i = 0; i < OBJ_NUM; i++) {
		addr[i] = kmem_cache_alloc(sock);
		assert (addr[i] != NULL);

                strcpy(addr[i], "hello, slab.");
                printf("[%5d] %s\n", i, addr[i]);
	}

	for (i = 0; i < OBJ_NUM; i++)
		kmem_cache_free(sock, addr[i]);

        for (i = 0; i < 100; i++) {
		addr[i] = kmem_cache_alloc(sock);
		assert (addr[i] != NULL);

                strcpy(addr[i], "hello, slab.");
                printf("[%5d] %s\n", i, addr[i]);
	}

/*
	gettimeofday(&eval, NULL);
	printf("%d:%d\t%d:%d\n", sval.tv_sec, sval.tv_usec,
				eval.tv_sec, eval.tv_usec);
*/
	//kmem_cache_destroy(main_thread_mem, sock);
	kmem_cache_list_destroy(main_thread_mem);
}

void kmem_cache_test1(void)
{
        struct slab_cache *sock;
        struct slab_cache *conn;
        void *addr[OBJ_NUM];
        int i;

        main_thread_mem = mem_cache_init(SLAB_SIZE_NUM);
        assert(main_thread_mem != NULL);

        sock = kmem_cache_create(main_thread_mem, "sock", 32);
        assert (sock != NULL);

        conn = kmem_cache_create(main_thread_mem, "conn", 128);
        assert (conn != NULL);

        for (i = 0; i < OBJ_NUM; i++) {
                addr[i] = kmem_cache_alloc(sock);
                assert (addr[i] != NULL);

                strcpy(addr[i], "hello, sock.");
                printf("[%5d] %s\n", i, addr[i]);
        }

        for (i = 0; i < OBJ_NUM; i++)
                kmem_cache_free(sock, addr[i]);

        for (i = 0; i < OBJ_NUM; i++) {
                addr[i] = kmem_cache_alloc(conn);
                assert (addr[i] != NULL);

                strcpy(addr[i], "hello, conn.");
                printf("[%5d] %s\n", i, addr[i]);
        }

        //kmem_cache_destroy(main_thread_mem, sock);
        kmem_cache_list_destroy(main_thread_mem);
}

int main(void)
{
	slab_test();
	//slab_vs_glibc(1);
	//kmem_cache_test();
	
	return 0;
}
