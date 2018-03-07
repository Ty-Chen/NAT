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
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/**
 * list_add    -     add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implenting stacks.
 */	
static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

/**
 * list_add_tail    -     add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is good for implenting queue.
 */	
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

/*
 * Delete a list entry by making the prev/nextentries
 * point to each other
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
 static inline void __list_del(struct list_head *prev, struct list_head *next)
 {
 	next->prev = prev;
	prev->next = next;
 }

/**
 * list_del    -    delete entry from list
 * @entry: the element to delete from the list
 * Note: list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POSITION1;
	entry->prev = LIST_POSITION2;
}

/* 
 * list_empty  - tests whether a list is empty
 * @head: the list to test
 */
static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}	

static inline void __list_splice(struct list_head *list, struct list_head *head)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;
	sturct list_head *at = head->next;
	first->prev = head;
	head->next = first;
	last->next = at;
	at->prev = last;
}
