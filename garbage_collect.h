#ifndef GARBAGE_COLLECT_H
#define GARBAGE_COLLECT_H

JVM_OBJECT *create_new_obj(void *addr, int size);
int inc_obj_ref(void *addr, struct list_head *list_head);
int dec_obj_ref(void *addr, struct list_head *list_head);

#endif
