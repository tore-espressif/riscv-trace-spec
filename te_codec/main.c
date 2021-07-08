#include "decoder-algorithm-public.h"
#include "te-elf-dis.h"
#include <assert.h>
#include "riscv-disas.h"
#include "esp_trace_decoder.h"
#include <unistd.h>
#include <libgen.h>

static te_elf_dis_file_t dis_file; // Disassembly file. Can be obtained with `riscv-none-embed-objdump -S -d elf_file.elf > dis_file.txt`

//----------------------- Decoder callbacks ----------------------------
unsigned esp_get_instruction(void *const user_data, const te_address_t address, rv_inst *const instruction){
    const te_elf_dis_tuple_t *tuple = te_find_one_elf_dis_tuple(&dis_file, address);
    assert(tuple);
    assert(address == tuple->address);
    *instruction = strtoll(tuple->line, NULL, 16);
    return (unsigned)inst_length((rv_inst) *instruction);
};

void esp_advance_decoded_pc(void *const user_data, const te_address_t old_pc, const te_address_t new_pc, const te_decoded_instruction_t *const new_instruction){
    // Nothing to do here
}

//--------------------------------- Main -------------------------------
int main(int argc, char *argv[])
{
    if (argc < 3) goto usage;

    // By default, this program assumes that a disassembly is passed to it.
    // It can also generate the disassembly in case an ELF file is passed to it.
    bool is_elf = false;
    int dump_arg_idx = 2;
    char * disassembly_file_name = argv[1];

    int opt;
    while ((opt = getopt(argc, argv, "e:")) != -1) {
        if (opt == 'e') {
            if (argc < 4) goto usage;         
            is_elf = true;
            disassembly_file_name = argv[2];
            dump_arg_idx = 3;
            continue;
        }

    // GCOV_EXCL_START
    usage:
        fprintf(stderr, "\nUsage: %s [-e] [disassembly_file] [trace_dump_file]\n\n", basename(argv[0]));
        exit(EXIT_FAILURE);
    // GCOV_EXCL_STOP
    }

    // Generate disassembly file from the ELF
    if (is_elf) {
        //FIXME: Very ugly processing of objdump output
        // -S, --source             Intermix source code with disassembly
        // -d, --disassemble        Display assembler contents of executable sections
        char cmd[100] = "riscv-none-embed-objdump -S -d ";
        strcat(cmd, disassembly_file_name);
        strcat(cmd, " > ");

        // Change file extension to .txt and save objdump output to it
        strcpy(&disassembly_file_name[strlen(disassembly_file_name) - 3], "txt");
        strcat(cmd, disassembly_file_name);

        // Run riscv-none-embed-objdump
        if (system(cmd) != 0){
            fprintf(stderr, "\nFollowing command:\n%s\nfailed.\n\n", cmd); // GCOV_EXCL_LINE
            exit(EXIT_FAILURE); // GCOV_EXCL_LINE
        }
    }

    // Open disassembly file
    if (te_read_one_elf_dis_file( &dis_file, disassembly_file_name) != 0){
        fprintf(stderr, "\nCould not open file %s.\n\n", disassembly_file_name); // GCOV_EXCL_LINE
        exit(EXIT_FAILURE); // GCOV_EXCL_LINE
    }

    // Process all passed trace files
    int num_of_trace_files = argc - dump_arg_idx;
    for (int i = 0; i < num_of_trace_files; i++, dump_arg_idx++) {
        // Open Trace dump file
        char *trace_dump_file_name = argv[dump_arg_idx];
        esp_trace_dump_t *trace = esp_trace_dump_open(trace_dump_file_name);
        if (trace == 0) {
            fprintf(stderr, "\nCould not open file %s.\n\n", trace_dump_file_name); // GCOV_EXCL_LINE
            exit(EXIT_FAILURE); // GCOV_EXCL_LINE
        }

        // Open and configure Trace decoder
        te_decoder_state_t *dec = te_open_trace_decoder(NULL, esp_get_instruction, NULL, esp_advance_decoded_pc, NULL, rv32);
        assert(dec);
        dec->debug_flags = TE_DEBUG_PC_TRANSITIONS | TE_DEBUG_IMPLICIT_RETURN | TE_DEBUG_FOLLOW_PATH | TE_DEBUG_PACKETS | TE_DEBUG_JUMP_TARGET_CACHE | TE_DEBUG_BRANCH_PREDICTION | TE_DEBUG_EXCEPTIONS;
        dec->debug_stream = stdout;       // Debug output to stdout
        dec->options.full_address = true; // Specific to Espressif. All reported addresses are absolute

        // Get packets from dump and process them
        printf("\nRISC-V trace decoder. Input files:\nDisassembly file: %s\nTrace dump: %s\n\n", disassembly_file_name, trace_dump_file_name);
        te_inst_t trace_packet;
        while (esp_trace_get_packet(&trace_packet, trace) != NULL) {
            te_process_te_inst(dec, &trace_packet);
            if (dec->error_code != TE_ERROR_OKAY)
                break; // GCOV_EXCL_LINE
        }
        
#if defined(TE_WITH_STATISTICS)
        te_print_decoded_cache_statistics(dec);
#endif
    exit:
        free(dec);
        esp_trace_dump_close(trace);
    }

    printf("\nExiting...\n\n");
    te_free_one_elf_dis_file(&dis_file);
    return 0;
}