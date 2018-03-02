#ifndef __C_LIST_H
#define __C_LIST_Htypedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long size_t;
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})

/* 
 * There are non-NULL pointers that will result in page faults
 * under normal circumstances, used to verify that nobody uses
 * non-initialized list entries
 */
#define LIST_POSITION1 ((void *) 0x00100100)
#define LIST_POSITION2 ((void *) 0x00200200)

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

/**
 * list_for_each	-	iterate over list 
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_for_each(pos, head) for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_r	-	iterate over list 
 *
 */
#define list_for_each_r(pos, head) for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we konw
 * the prev/next entries already
 */
static inline void __list_add(struct list_head *new,
			     struct list_head *prev,
			     struct list_head *next)
