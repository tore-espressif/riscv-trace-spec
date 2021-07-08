#pragma once
typedef struct {
    uint8_t *hex_trace;
    uint8_t *ptr;
    size_t hex_trace_len;
} esp_trace_dump_t;

uint8_t *esp_trace_get_packet(te_inst_t *packet_out, esp_trace_dump_t *td);
esp_trace_dump_t *esp_trace_dump_open(const char * const f_name);
void esp_trace_dump_close(esp_trace_dump_t *td);