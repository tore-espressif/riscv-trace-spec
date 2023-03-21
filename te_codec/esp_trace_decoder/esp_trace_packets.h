#pragma once

#include <stdint.h>

#define TRACE_PACKET_HEADER_LEN (3) // 1: length + 2: index
typedef struct __attribute__((packed)) {
    uint8_t header;
    uint16_t index;
    uint8_t payload[];
} esp_packet_base_t;

typedef union __attribute__((packed)){
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t subformat : 2;
        uint64_t branch : 1;
        uint64_t privilege : 1;
        uint64_t address : 31;
        uint64_t sign_extend : 3;
    } data ;
    uint8_t raw[5];   
} esp_packet_3_0_t ;

typedef union __attribute__((packed)){
    struct __attribute__((packed)){
        int format : 2;
        int subformat : 2;
        int branch : 1;
        int privilege : 1;
        int ecause : 6;
        int interrupt : 1;
        int theaddr : 1;
        int address : 31;
        int tvalepc : 32; // not present if interrupt = 1
        int sign_extend : 3;
    } data;
    uint8_t raw[10];
} esp_packet_3_1_t;

typedef union __attribute__((packed)){
    struct __attribute__((packed)){
        int format : 2;
        int subformat : 2;
        int ienable : 1;
        int encoder_mode : 1;
        int qual_status : 2;
        int ioptions : 6; // b0: implicit return, b1: implicit exception, b2: full address, b3: jump target cache, b4: branch prediction, b5: seq. inferred jumps
        int sign_extend : 2;
    } data;
    uint8_t raw[2];
} esp_packet_3_3_t;

#define PACKET_2_ADDRESS_OFFSET 1
typedef union __attribute__((packed)){
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t notify : 1;
        uint64_t updiscon : 1;
        uint64_t sign_extend : 4;
        uint64_t address : 32;
    } data;
    uint8_t raw[5];
} esp_packet_2_t;

typedef union __attribute__((packed)){
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t branches : 5;
        uint64_t branch_map : 31;
        uint64_t sign_extend : 2;
    } data;
    uint8_t raw[5];
} esp_packet_1_0_t;

#define PACKET_1_1_ADDRESS_OFFSET 2
typedef union __attribute__((packed)){
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t branches : 5;
        uint64_t branch_map : 1;
        uint64_t notify : 1;
        uint64_t updiscon : 1;
        uint64_t sign_extend : 6;
        uint64_t address : 32;
    } data;
    uint8_t raw[6];
} esp_packet_1_1_t;

#define PACKET_1_2_3_ADDRESS_OFFSET 2
typedef union __attribute__((packed)){
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t branches : 5;
        uint64_t branch_map : 3;
        uint64_t notify : 1;
        uint64_t updiscon : 1;
        uint64_t sign_extend : 4;
        uint64_t address : 32;
    } data;
    uint8_t raw[6];
} esp_packet_1_2_3_t;

#define PACKET_1_4_7_ADDRESS_OFFSET 2
typedef union __attribute__((packed)){
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t branches : 5;
        uint64_t branch_map : 7;
        uint64_t notify : 1;
        uint64_t updiscon : 1;
        uint64_t address : 32;
    } data;
    uint8_t raw[6];
} esp_packet_1_4_7_t;

#define PACKET_1_8_15_ADDRESS_OFFSET 3
typedef union __attribute__((packed)){
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t branches : 5;
        uint64_t branch_map : 15;
        uint64_t notify : 1;
        uint64_t updiscon : 1;
        uint64_t address : 32;
    } data;
    uint8_t raw[7];
} esp_packet_1_8_15_t;

#define PACKET_1_16_31_ADDRESS_OFFSET 5
typedef union __attribute__((packed)){
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t branches : 5;
        uint64_t branch_map : 31;
        uint64_t notify : 1;
        uint64_t updiscon : 1;
        uint64_t address : 32;
    } data ;
    uint8_t raw[9];
} esp_packet_1_16_31_t;
