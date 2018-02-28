#ifndef __C_LIST_H
#define __C_LIST_Htypedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long size_t;
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) (type *)((char *)ptr -offsetof(type, member))
