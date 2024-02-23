#ifndef _TYPES_H
#define _TYPES_H

typedef enum {
    DIRECTION_IN = 0x01,
    DIRECTION_OUT = 0x02,
    DIRECTION_ANY = DIRECTION_IN | DIRECTION_OUT,
} __attribute__((packed)) direction_t;

typedef enum {
    PROT_ICMP = 1,
    PROT_TCP = 6,
    PROT_UDP = 17,
    PROT_OTHER = 255,
    PROT_ANY = 143,
} __attribute__((packed)) prot_t;

#endif // _TYPES_H
