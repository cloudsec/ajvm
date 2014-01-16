/*
 * garbage_collect.c - an sample memroy garbage collection.
 *
 * (c) wzt 2014         http://www.cloud-sec.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wvm.h"
#include "type.h"
#include "list.h"
#include "log.h"
#include "vm_error.h"
#include "garbage_collect.h"

JVM_OBJECT *create_new_obj(void *addr, int size)
{
	JVM_OBJECT *new_obj = NULL;

        new_obj = (JVM_OBJECT *)calloc(1, sizeof(JVM_OBJECT));
        if (!new_obj) {
                error("calloc failed.\n");
                return NULL;
        }

        new_obj->addr = (void *)addr;
        new_obj->size = size;
        new_obj->ref_count = 0;

        list_add_tail(&(new_obj->list), &jvm_obj_list_head);

	return new_obj;
}

void free_jvm_obj(JVM_OBJECT *obj)
{
	if (obj)
		free((void *)obj);
}

void show_jvm_obj(struct list_head *list_head)
{
	JVM_OBJECT *s;
	struct list_head *p;

	list_for_each(p, list_head) {
		s = list_entry(p, JVM_OBJECT, list);
		if (s) {
			printf("addr: 0x%x\tsize: %d\tref_count: %d\n", 
				s->addr, s->size, s->ref_count);
		}
	}
}

void del_jvm_obj(struct list_head *list_head, void *addr)
{
        JVM_OBJECT *s;
        struct list_head *p, *q;

        list_for_each_safe(p, q, list_head) {
                s = list_entry(p, JVM_OBJECT, list);
                if (s && s->addr == addr) {
                        printf("found addr: 0x%x\tsize: %d\tref_count: %d\n",
                                s->addr, s->size, s->ref_count);
			list_del(p);
			free_jvm_obj(s);
                }
        }
}

void free_all_jvm_obj(struct list_head *list_head, void *addr)
{
        JVM_OBJECT *s;
        struct list_head *p, *q;

        list_for_each_safe(p, q, list_head) {
                s = list_entry(p, JVM_OBJECT, list);
                if (s) {
                        list_del(p);
                        free_jvm_obj(s);  
                }
        }
}

JVM_OBJECT *search_obj_by_addr(void *addr, struct list_head *list_head)
{
	JVM_OBJECT *s;
	struct list_head *p;

	list_for_each(p, list_head) {
		s = list_entry(p, JVM_OBJECT, list);
		if (s && s->addr == addr) {
			printf("found addr: 0x%x\tsize: %d\tref_count: %d\n", 
				s->addr, s->size, s->ref_count);
			return s;
		}
	}
	printf("not found addr: 0x%x\n", addr);

	return NULL;
}

int inc_obj_ref(void *addr, struct list_head *list_head)
{
	JVM_OBJECT *obj;

	obj = search_obj_by_addr(addr, list_head);
	if (!obj)
		return -1;

	obj->ref_count++;
	return 0;
}

int dec_obj_ref(void *addr, struct list_head *list_head)
{
	JVM_OBJECT *obj;

	obj = search_obj_by_addr(addr, list_head);
	if (!obj)
		return -1;

	obj->ref_count--;
	return 0;
}

void start_gc(struct list_head *list_head)
{
	JVM_OBJECT *s;
	struct list_head *p, *q;

	list_for_each_safe(p, q, list_head) {
		s = list_entry(p, JVM_OBJECT, list);
		if (s && s->ref_count == 0) {
			printf("free addr: 0x%x\tsize: %d\tref_count: %d\n", 
				s->addr, s->size, s->ref_count);
                        list_del(p);
                        free_jvm_obj(s);  
		}
	}
}
