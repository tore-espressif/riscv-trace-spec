#include "decoder-algorithm-public.h"
#include "assert.h"
#include "stdint.h"
#include "stdio.h"
#include "esp_trace_decoder.h"

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
    uint8_t raw[8];   
} esp_packet_3_0_t ;

typedef union __attribute__((packed)){
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t address : 31;
        uint64_t notify : 1;
        uint64_t updiscon : 1;
        uint64_t sign_extend : 5;
    } data ;
    uint8_t raw[5];
} esp_packet_2_t;

typedef union __attribute__((packed)){
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t branches : 5;
        uint64_t branch_map : 31;
        uint64_t sign_extend : 2;
    } b_0;
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t branches : 5;
        uint64_t branch_map : 1;
        uint64_t address : 31;
        uint64_t notify : 1;
        uint64_t updiscon : 1;
        uint64_t sign_extend : 7;
    } b_1;
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t branches : 5;
        uint64_t branch_map : 3;
        uint64_t address : 31;
        uint64_t notify : 1;
        uint64_t updiscon : 1;
        uint64_t sign_extend : 5;
    } b_2_3;
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t branches : 5;
        uint64_t branch_map : 7;
        uint64_t address : 31;
        uint64_t notify : 1;
        uint64_t updiscon : 1;
        uint64_t sign_extend : 1;
    } b_4_7;
    struct __attribute__((packed)){
        uint64_t format : 2;
        uint64_t branches : 5;
        uint64_t branch_map : 15;
        uint64_t address : 31;
        uint64_t notify : 1;
        uint64_t updiscon : 1;
        uint64_t sign_extend : 1;
    } b_8_15;
    struct __attribute__((packed)){
        __uint128_t format : 2;
        __uint128_t branches : 5;
        __uint128_t branch_map : 31;
        __uint128_t address : 31;
        __uint128_t notify : 1;
        __uint128_t updiscon : 1;
        __uint128_t sign_extend : 1;
    } b_16_31;
} esp_packet_1_t;

static uint8_t esp_decode_packet_3(te_inst_t *out, const uint8_t *payload)
{
    out->subformat = (payload[0] & 0x0C) >> 2;
    switch (out->subformat)
    {
    case 3: // Subformat 3
    {
        out->support.i_enable = payload[0] & 0x10;
        out->support.qual_status = (payload[0] & 0x60) >> 5;
        out->support.options.full_address = true; //@todo always full address in chip 9.1
        return 1;
    }
    case 1: // Subformat 1
    {
        out->branch    = payload[0] &0x10;
        out->privilege = (payload[0] &0x20) >> 5;
        out->ecause    = ((payload[0] & 0xC0) >> 6) | ((payload[1] & 0x07) << 2);
        out->interrupt = payload[1] &0x08;
        out->address   = (payload[1] >> 4) | (payload[2] << 4) | (payload[3] << 12) | (payload[4] << 20) | ((payload[5] & 0x07) << 28);
        out->tvalepc   = ((payload[5] & 0xF8) >> 3) | (payload[6] << 5) | (payload[7] << 13) | (payload[8] << 21) | ((payload[9] & 0x07) << 29);
        return 10;
    }

    case 0: // Subformat 0
    {
        esp_packet_3_0_t *pac = (esp_packet_3_0_t *)payload;
        out->branch    = pac->data.branch;
        out->privilege = pac->data.privilege;
        out->address   = pac->data.address;
        return 5;
    }
    default: return 0; // GCOV_EXCL_LINE
    }
}

static uint8_t esp_decode_packet_2(te_inst_t *out, const uint8_t *payload) {
    esp_packet_2_t *pac = (esp_packet_2_t *)payload;
    out->address = pac->data.address;
    out->notify = pac->data.notify;
    out->updiscon = pac->data.updiscon;
    return 5;
}

static uint8_t esp_decode_packet_1(te_inst_t *out, const uint8_t *payload) {

    uint8_t ret  = 0;
    esp_packet_1_t *pac = (esp_packet_1_t *)payload;
    out->branches = pac->b_1.branches;
    switch (out->branches) {
        case 0:
            out->branch_map = pac->b_0.branch_map;
            ret = 5;
            break;
        case 1:             
            out->branch_map = pac->b_1.branch_map;
            out->address    = pac->b_1.address;
            out->notify     = pac->b_1.notify;
            out->updiscon   = pac->b_1.updiscon;
            ret = 6;
            break;
        case 2 ... 3:
            out->branch_map = pac->b_2_3.branch_map;
            out->address    = pac->b_2_3.address;
            out->notify     = pac->b_2_3.notify;
            out->updiscon   = pac->b_2_3.updiscon;
            ret = 6;
        break;
        case 4 ... 7:
            out->branch_map = pac->b_4_7.branch_map;
            out->address    = pac->b_4_7.address;
            out->notify     = pac->b_4_7.notify;
            out->updiscon   = pac->b_4_7.updiscon;
            ret = 6;
            break;
        case 8 ... 15:
            out->branch_map = pac->b_8_15.branch_map;
            out->address    = pac->b_8_15.address;
            out->notify     = pac->b_8_15.notify;
            out->updiscon   = pac->b_8_15.updiscon;
            ret = 7;
            break;
        case 16 ... 31:
            out->branch_map = pac->b_16_31.branch_map;
            out->address    = pac->b_16_31.address;
            out->notify     = pac->b_16_31.notify;
            out->updiscon   = pac->b_16_31.updiscon;
            ret = 9;
            break;
        default: break; // GCOV_EXCL_LINE
    }
    return ret;
}

esp_trace_dump_t *esp_trace_dump_open(const char * const f_name) {
    FILE *trace_file = fopen(f_name, "r");
    if (!trace_file) {
        return NULL; // GCOV_EXCL_LINE
    }

    // We assume that the trace dump is a one-liner
    fseek(trace_file, 0L, SEEK_END);
    long file_size = ftell(trace_file);
    rewind(trace_file);
    char *dump = malloc(file_size);
    assert(dump);
    fgets(dump, file_size, trace_file);

    esp_trace_dump_t *esp_trace_dump = malloc(sizeof(esp_trace_dump_t));
    assert(esp_trace_dump_open);
    esp_trace_dump->hex_trace = malloc(file_size / 2);
    assert(esp_trace_dump->hex_trace);
    
    // Convert hex-string into bytes
    int i = 0;
    while (1) {
        if (dump[2*i] == '\0') break;
        char t[3];
        strncpy(t, dump + 2*i, 2);
        t[2] = '\0';
        esp_trace_dump->hex_trace[i] = strtol(t, NULL, 16);
        i++;
    };
    esp_trace_dump->hex_trace_len = i;
    esp_trace_dump->ptr = esp_trace_dump->hex_trace;
    free(dump);
    fclose(trace_file);
    return esp_trace_dump;
}

void esp_trace_dump_close(esp_trace_dump_t *td) {
    free(td->hex_trace);
    free(td);
}

uint8_t *esp_trace_get_packet(te_inst_t *packet_out, esp_trace_dump_t *td) {

    assert(td);
    assert(packet_out);

    // Process zero packet
    if (*td->ptr == 0) {
        td->ptr += 14;
    }
    if (td->ptr >= (td->hex_trace + td->hex_trace_len)) {
        return NULL;
    }

    // Zeroize output
    memset(packet_out, 0, sizeof(te_inst_t));

    esp_packet_base_t *base_packet = (esp_packet_base_t *)td->ptr;
    packet_out->format = base_packet->payload[0] & 0x03;
    int packet_len;
    switch (packet_out->format) {
    case 3: // Packet format 3
        packet_len = esp_decode_packet_3(packet_out, base_packet->payload);
        break;
    case 2: // Packet format 2
        assert(base_packet->header == 8);
        packet_len = esp_decode_packet_2(packet_out, base_packet->payload);
        break;
    case 1: // Packet format 1
        packet_len = esp_decode_packet_1(packet_out, base_packet->payload);
        break;
    default: return NULL; // GCOV_EXCL_LINE
    }

    assert((packet_len + 3) == base_packet->header);
    td->ptr += base_packet->header;
    return (uint8_t*)packet_out;
}
