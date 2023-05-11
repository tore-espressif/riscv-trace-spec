#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "esp_trace_decoder.h"
#include "esp_trace_packets.h"

#ifndef BIT
#define BIT(n)      (1UL << (n))
#endif

// Get MSB out of x-bit wide address field
#define ADDR_MSB(addr, addr_bit_width) ((addr & BIT(addr_bit_width - 1)) >> (addr_bit_width - 1))

/**
 * @brief Get the address from packet object
 *
 * The address field in trace packets with delta encoding has variable length: 8-32 bits.
 * This is a helper function that will retrieve correct address value from pointer to the address field and its bit width.
 *
 * @param[in] address             Pointer to address field
 * @param[in] address_bit_width   Length of address in bytes. Can be 8, 16, 24 or 32.
 * @return uint64_t               Parsed address value
 */
static uint64_t get_address_from_packet(void *address, int address_bit_width)
{
    if (address == NULL) {
        return 0;
    }

    switch (address_bit_width) {
        case 8: {
            int8_t *_addr = (int8_t *) address;
            return (uint64_t)*_addr;
        }
        case 16: {
            int16_t *_addr = (int16_t *) address;
            return (uint64_t)*_addr;
        }
        case 24: {
            uint32_t _addr = *((uint32_t *) address);
            // Data is little-endian. We need to get top 3 bytes
            _addr &= 0x00FFFFFF;
            return (uint64_t)_addr;
        }
        case 32: {
            int32_t *_addr = (int32_t *) address;
            return (uint64_t)*_addr;
        }
        default: return 0;
    }
}

static uint8_t esp_decode_packet_3(te_inst_t *out, const uint8_t *payload, int packet_len)
{
    out->subformat = (payload[0] & 0x0C) >> 2;
    switch (out->subformat) {
    case 3: // Subformat 3
    {
        esp_packet_3_3_t *pac = (esp_packet_3_3_t *)payload;
        out->support.i_enable = pac->data.ienable;
        out->support.qual_status = pac->data.qual_status;
        out->support.options.implicit_return = BIT(0) & pac->data.ioptions;
        out->support.options.implicit_exception = BIT(1) & pac->data.ioptions;
        out->support.options.full_address = BIT(2) & pac->data.ioptions;
        out->support.options.jump_target_cache = BIT(3) & pac->data.ioptions;
        out->support.options.branch_prediction = BIT(4) & pac->data.ioptions;
        out->support.encoder_mode = pac->data.encoder_mode;
        return 2;
    }
    case 1: // Subformat 1
    {
        esp_packet_3_1_t *pac = (esp_packet_3_1_t *)payload;
        out->branch    = pac->data.branch;
        out->privilege = pac->data.privilege;
        out->ecause    = pac->data.ecause;
        out->interrupt = pac->data.interrupt;
        if (!pac->data.theaddr) {
            //@todo there is another theaddr field. ???
            assert(!"there is another theaddr field in the packet that is not implemented in the decoder yet");
        }
        out->address   = pac->data.address;
        //printf("[Debug] Packet format 3, subformat 1. Branch :%d, Privilege: %d, Ecause %d, Interrupt %d, theaddr: %s, Address: 0x%08X\n", out->branch, out->privilege, out->ecause, out->interrupt, pac->data.theaddr ? "true":"false", out->address);
        // The format 3 subformat 1 packet length is variable.
        // if interrupt == 1, the tvalepc field is omitted
        if (out->interrupt == 1) {
            return 6;
        } else {
            out->tvalepc   = pac->data.tvalepc;
            return 10;
        }
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

static uint8_t esp_decode_packet_2(te_inst_t *out, const uint8_t *payload, int packet_len)
{
    esp_packet_2_t *pac = (esp_packet_2_t *)payload;
    const int addr_offset = PACKET_2_ADDRESS_OFFSET;
    const int addr_len = packet_len - TRACE_PACKET_HEADER_LEN - addr_offset;
    out->address  = get_address_from_packet((void *)&(pac->raw[addr_offset]), addr_len * 8 ); // Taking address of bitfield is not allowed, so we cannot do &(pac->data.address)
    out->notify   = (bool)(pac->data.notify ^ ADDR_MSB(out->address, addr_len * 8));
    out->updiscon = (bool)(pac->data.updiscon ^ pac->data.notify);
    printf("[Debug] Packet format 2, notify: %u, updiscon: %u\n", out->notify, out->updiscon);
    return addr_len + addr_offset;
}

static uint8_t esp_decode_packet_1(te_inst_t *out, const uint8_t *payload, int packet_len)
{
    esp_packet_1_0_t *temp_pac = (esp_packet_1_0_t *)payload;
    out->branches = temp_pac->data.branches;
    //printf("[Debug] Packet format 1, branches: %d, packet length: %d\n", out->branches, packet_len);
    switch (out->branches) {
        case 0: {
            esp_packet_1_0_t *pac = (esp_packet_1_0_t *)payload;
            out->branch_map = pac->data.branch_map;
            return 5;
        }
        case 1: {
            esp_packet_1_1_t *pac = (esp_packet_1_1_t *)payload;
            const int addr_offset = PACKET_1_1_ADDRESS_OFFSET;
            const int addr_len    = packet_len - TRACE_PACKET_HEADER_LEN - addr_offset;
            out->address    = get_address_from_packet((void *)&(pac->raw[addr_offset]), addr_len * 8 );
            out->branch_map = pac->data.branch_map;
            out->notify     = (bool)(pac->data.notify ^ ADDR_MSB(out->address, addr_len * 8));
            out->updiscon   = (bool)(pac->data.updiscon ^ pac->data.notify);
            return addr_offset + addr_len;
        }
        case 2 ... 3: {
            esp_packet_1_2_3_t *pac = (esp_packet_1_2_3_t *)payload;
            const int addr_offset = PACKET_1_2_3_ADDRESS_OFFSET;
            const int addr_len    = packet_len - TRACE_PACKET_HEADER_LEN - addr_offset;
            out->address    = get_address_from_packet((void *)&(pac->raw[addr_offset]), addr_len * 8 );
            out->branch_map = pac->data.branch_map;
            out->notify     = (bool)(pac->data.notify ^ ADDR_MSB(out->address, addr_len * 8));
            out->updiscon   = (bool)(pac->data.updiscon ^ pac->data.notify);
            if (out->notify) {
                printf("NOTIFY ASSERTED\n");
            }
            return addr_offset + addr_len;
        }
        case 4 ... 7: {
            esp_packet_1_4_7_t *pac = (esp_packet_1_4_7_t *)payload;
            const int addr_offset = PACKET_1_4_7_ADDRESS_OFFSET;
            const int addr_len    = packet_len - TRACE_PACKET_HEADER_LEN - addr_offset;
            out->address    = get_address_from_packet((void *)&(pac->raw[addr_offset]), addr_len * 8 );
            out->branch_map = pac->data.branch_map;
            out->notify     = (bool)(pac->data.notify ^ ADDR_MSB(out->address, addr_len * 8));
            out->updiscon   = (bool)(pac->data.updiscon ^ pac->data.notify);
             if (out->notify) {
                printf("NOTIFY ASSERTED\n");
            }
            return addr_offset + addr_len;
        }
        case 8 ... 15: {
            esp_packet_1_8_15_t *pac = (esp_packet_1_8_15_t *)payload;
            const int addr_offset = PACKET_1_8_15_ADDRESS_OFFSET;
            const int addr_len    = packet_len - TRACE_PACKET_HEADER_LEN - addr_offset;
            out->address    = get_address_from_packet((void *)&(pac->raw[addr_offset]), addr_len * 8 );
            out->branch_map = pac->data.branch_map;
            out->notify     = (bool)(pac->data.notify ^ ADDR_MSB(out->address, addr_len * 8));
            out->updiscon   = (bool)(pac->data.updiscon ^ pac->data.notify);
            return addr_offset + addr_len;
        }
        case 16 ... 31: {
            esp_packet_1_16_31_t *pac = (esp_packet_1_16_31_t *)payload;
            const int addr_offset = PACKET_1_16_31_ADDRESS_OFFSET;
            const int addr_len    = packet_len - TRACE_PACKET_HEADER_LEN - addr_offset;
            out->address    = get_address_from_packet((void *)&(pac->raw[addr_offset]), addr_len * 8 );
            out->branch_map = pac->data.branch_map;
            out->notify     = (bool)(pac->data.notify ^ ADDR_MSB(out->address, addr_len * 8));
            out->updiscon   = (bool)(pac->data.updiscon ^ pac->data.notify);
            return addr_offset + addr_len;
        }
        default: return 0; // GCOV_EXCL_LINE
    }
}

esp_trace_dump_t *esp_trace_dump_open(const char * const f_name)
{
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

void esp_trace_dump_close(esp_trace_dump_t *td)
{
    free(td->hex_trace);
    free(td);
}

uint8_t *esp_trace_get_packet(te_inst_t *packet_out, esp_trace_dump_t *td)
{
    assert(td);
    assert(packet_out);

    if (td->ptr >= (td->hex_trace + td->hex_trace_len)) {
        printf("[Debug] End of trace.hex\n");
        return NULL;
    }
    esp_packet_base_t *base_packet = (esp_packet_base_t *)td->ptr;
    int packet_len = 0x1F & base_packet->header;
    if (packet_len == 0) {
        printf("[Debug] Packet len == 0\n");
        return NULL;
    }

    // Zeroize output
    memset(packet_out, 0, sizeof(te_inst_t));
    packet_out->format = base_packet->payload[0] & 0x03;

    int bytes_parsed = 0;
    switch (packet_out->format) {
    case 3: // Packet format 3
        bytes_parsed = esp_decode_packet_3(packet_out, base_packet->payload, packet_len);
        break;
    case 2: // Packet format 2
        bytes_parsed = esp_decode_packet_2(packet_out, base_packet->payload, packet_len);
        break;
    case 1: // Packet format 1
        bytes_parsed = esp_decode_packet_1(packet_out, base_packet->payload, packet_len);
        break;
    case 0:
        return NULL; // End of Trace data
    default:
        fprintf(stderr, "\033[0;31m[Error] Unexpected packet format: %d. Aborting... \033[0m\n", packet_out->format);
        return NULL; // GCOV_EXCL_LINE
    }

    if ((bytes_parsed + TRACE_PACKET_HEADER_LEN) != packet_len) {
        fprintf(stderr, "\033[0;31m[Error] Unexpected packet length. Expected %d, got:%d, packet format: %d\033[0m\n", packet_len, bytes_parsed + TRACE_PACKET_HEADER_LEN, packet_out->format);
        return NULL;
    }

    // #if defined(TE_WITH_STATISTICS)
    //printf("[Debug] Decoded packet: Length %d, Index: %d, Format: %d, Subformat: %d\n", packet_len, base_packet->index, packet_out->format, packet_out->subformat);
    //#endif

    td->ptr += packet_len;
    return (uint8_t*)packet_out;
}
