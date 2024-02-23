#ifndef _DIRECTION_H_
#define _DIRECTION_H_

typedef enum {
    DIRECTION_IN = 0x01,
    DIRECTION_OUT = 0x02,
    DIRECTION_ANY = DIRECTION_IN | DIRECTION_OUT,
} __attribute__((packed)) direction_t;

#endif // _DIRECTION_H_
