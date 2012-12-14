#ifndef LIST_H
#define LIST_H

#include <stddef.h>

struct list_head {
        struct list_head *prev, *next;
};


#define INIT_LIST_HEAD(name_ptr)                do {    (name_ptr)->next = (name_ptr);  \
                                                        (name_ptr)->prev = (name_ptr);  \
                                                }while (0)


#define OFFSET(type, member)                    (char *)&(((type *)0x0)->member)
#define container_of(ptr, type, member)         ({(type *)((char * )ptr - OFFSET(type, member)); });

#define list_for_each(pos, head)                for (pos = head->next; pos != head; pos = pos->next)
#define list_for_each_prev(pos, head)           for (pos = head->prev; pos != head; pos = pos->prev)
#define list_for_each_safe(pos, n, head)        for (pos = head->next, n = pos->next; pos != head; pos = n, n = pos->next)
#define list_entry(ptr, type, member)           container_of(ptr, type, member)

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
        head->prev->next = new;
        new->prev = head->prev;
        new->next = head;
        head->prev = new;
}

static inline void list_add_tail1(struct list_head *new, struct list_head *head)
{
        new->next = head;
        new->prev = head->prev;
        head->prev->next = new;
        head->prev = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
        new->next = head->next;
        new->prev = head;
        head->next->prev = new;
        head->next = new;
}

static inline void list_del(struct list_head *p)
{
        p->prev->next = p->next;
        p->next->prev = p->prev;
}

static inline int list_empty(struct list_head *head)
{
        return head->next == head;
}

#define FREE_LIST(type, link_head) {                            \
        type *p = NULL;                                         \
        struct list_head *s = NULL;                             \
        struct list_head *q = NULL;                             \
        for (s = (&link_head)->next; s != &link_head; s = q) {  \
                if (!s)                                         \
                        return ;                                \
                q = s->next;                                    \
                p = list_entry(s, type, list);                  \
                if (p) {                                        \
                        list_del(s);                            \
                        free(p);                                \
                        p = NULL;                               \
                }                                               \
        }}

#define FREE_LIST_SAFE(type, link_head) {                       \
	{							\
        type *p = NULL;                                         \
        struct list_head *s = NULL;                             \
        struct list_head *q = NULL;                             \
        list_for_each_safe(s, q, (&link_head)) {                \
                p = list_entry(s, type, list);                  \
                if (p) {                                        \
                        list_del(s);                            \
                        free(p);                                \
                }                                               \
        }}							\
	}

#endif
