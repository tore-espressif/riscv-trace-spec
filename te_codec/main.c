#include "decoder-algorithm-public.h"
#include "encoder-algorithm-public.h"
#include "te-elf-dis.h"
#include <assert.h>
#include "riscv-disas.h"
#include "esp_trace_decoder.h"
#include <unistd.h>
#include <libgen.h>

static te_elf_dis_file_t dis_file; // Disassembly file. Can be obtained with `riscv-none-embed-objdump -S -d elf_file.elf > dis_file.txt`

//----------------------- Decoder callbacks ----------------------------
unsigned esp_get_instruction(void *const user_data, const te_address_t address, rv_inst *const instruction){
    te_address_t address_32 = address & 0xFFFFFFFF; // ESP uses 32 bit addressing
    const te_elf_dis_tuple_t *tuple = te_find_one_elf_dis_tuple(&dis_file, address_32);
    if(!tuple) {
        fprintf(stderr,"\033[0;31m[Error] Cannot find instruction at address 0x%08X.\033[0m\n", address_32);
        *instruction = rv_op_illegal;
        return 0;
    }
    assert(address_32 == tuple->address);
    *instruction = strtoll(tuple->line, NULL, 16);
    return (unsigned)inst_length((rv_inst) *instruction);
};

void esp_advance_decoded_pc(void *const user_data, const te_address_t old_pc, const te_address_t new_pc, const te_decoded_instruction_t *const new_instruction){
    // Nothing to do here
}

int esp_encoder_mode();

//--------------------------------- Main -------------------------------
int main(int argc, char *argv[])
{
    if (argc < 2) goto usage;

    // By default, this program assumes that a disassembly is passed to it.
    // It can also generate the disassembly in case an ELF file is passed to it.
    bool is_elf = false;

    // Be default, this program assumes that it will be in decoder mode
    // It can be used as encoder too
    bool encoder_mode = false;
    int dump_arg_idx = 2;
    char * disassembly_file_name = argv[1];

    int opt;
    while ((opt = getopt(argc, argv, "re:")) != -1) {
        if (opt == 'e') {
            if (argc < 4) goto usage;         
            is_elf = true;
            disassembly_file_name = argv[2];
            dump_arg_idx = 3;
            continue;
        }
        if (opt == 'r') {
            encoder_mode = true;
            continue;
        }

    // GCOV_EXCL_START
    usage:
        fprintf(stderr, "\nUsage decoder mode: %s [-e] [disassembly_file] [trace_dump_file]\n", basename(argv[0]));
        fprintf(stderr, "Usage encoder mode: %s [-r]\n\n", basename(argv[0]));
        exit(EXIT_FAILURE);
    // GCOV_EXCL_STOP
    }

    if (encoder_mode) {
        printf("\n\n\033[0;32mRISC-V trace encoder\033[0m\n\n");
        return esp_encoder_mode();
    } else {

        // Generate disassembly file from the ELF
        if (is_elf)
        {
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
            if (system(cmd) != 0)
            {
                fprintf(stderr, "\n[Error] Following command:\n%s\nfailed.\n\n", cmd); // GCOV_EXCL_LINE
                exit(EXIT_FAILURE);                                                    // GCOV_EXCL_LINE
            }
        }

        // Open disassembly file
        if (te_read_one_elf_dis_file(&dis_file, disassembly_file_name) != 0)
        {
            fprintf(stderr, "\n[Error] Could not open file %s.\n\n", disassembly_file_name); // GCOV_EXCL_LINE
            exit(EXIT_FAILURE);                                                              // GCOV_EXCL_LINE
        }

        // Process all passed trace files
        int num_of_trace_files = argc - dump_arg_idx;
        int num_of_trace_errors = 0;
        for (int i = 0; i < num_of_trace_files; i++, dump_arg_idx++)
        {
            // Open Trace dump file
            char *trace_dump_file_name = argv[dump_arg_idx];
            esp_trace_dump_t *trace = esp_trace_dump_open(trace_dump_file_name);
            if (trace == 0)
            {
                fprintf(stderr, "\n[Error] Could not open file %s.\n\n", trace_dump_file_name); // GCOV_EXCL_LINE
                exit(EXIT_FAILURE);                                                             // GCOV_EXCL_LINE
            }

            // Open and configure Trace decoder
            te_decoder_state_t *dec = te_open_trace_decoder(NULL, esp_get_instruction, NULL, esp_advance_decoded_pc, NULL, rv32);
            assert(dec);
            dec->debug_flags = TE_DEBUG_PC_TRANSITIONS | TE_DEBUG_IMPLICIT_RETURN | TE_DEBUG_FOLLOW_PATH | TE_DEBUG_PACKETS | TE_DEBUG_JUMP_TARGET_CACHE | TE_DEBUG_BRANCH_PREDICTION | TE_DEBUG_EXCEPTIONS;
            dec->debug_stream = stdout;       // Debug output to stdout
            dec->options.full_address = true; // Specific to Espressif. All reported addresses are absolute

            // Get packets from dump and process them
            printf("\n\n\033[0;32mRISC-V trace decoder. Input files:\nDisassembly file: %s\nTrace dump: %s\033[0m\n\n", disassembly_file_name, trace_dump_file_name);
            te_inst_t trace_packet;
            while (esp_trace_get_packet(&trace_packet, trace) != NULL)
            {
                te_process_te_inst(dec, &trace_packet);
                if (dec->error_code != TE_ERROR_OKAY)
                {
                    fprintf(stderr, "\033[0;31m");
                    fprintf(stderr, "\n[Error] te_process_te_inst function failed with exit code %d\n", dec->error_code);
                    fprintf(stderr, "\033[0m");
                    num_of_trace_errors++;
                    break;
                }
            }

#if defined(TE_WITH_STATISTICS)
            printf("\n[Debug] Statistics:\n");
            printf("[Debug] Number of Uninferrable PC discontinuities: %d\n", dec->statistics.num_updiscons);
            printf("[Debug] Number of trace packets: Format 1: %d, Format 2: %d, Format 3: %d\n", dec->statistics.num_format[1], dec->statistics.num_format[2], dec->statistics.num_format[3]);
            printf("[Debug] Number of Format 3 packets: Subformat 0: %d, Subformat 1: %d, Subformat 3: %d\n", dec->statistics.num_subformat[0], dec->statistics.num_subformat[1], dec->statistics.num_subformat[3]);
            printf("[Debug] Number of retired instructions: %d\n", dec->statistics.num_instructions);
            printf("[Debug] Number of exceptions: %d\n", dec->statistics.num_exceptions);
            printf("[Debug] Number of taken_branches/branches: %d/%d\n", dec->statistics.num_taken, dec->statistics.num_branches);
            printf("[Debug] Number of returns/calls: %d/%d\n", dec->statistics.num_returns, dec->statistics.num_calls);
#endif
        exit:
            free(dec);
            esp_trace_dump_close(trace);
        }

        printf("\n[Info] Decoded %d/%d traces successfully.\n", num_of_trace_files - num_of_trace_errors, num_of_trace_files);
        if (num_of_trace_errors != 0)
        {
            fprintf(stderr, "\033[0;31m[Error] Failed to decode %d traces.\033[0m\n", num_of_trace_errors);
        }
        printf("\n");
        te_free_one_elf_dis_file(&dis_file);
        return 0;
    }
}

void esp_emit_inst(
    void * const user_data,
    const te_inst_t * const te_inst) {
        printf("Packet format: %d\n", te_inst->format);
        switch (te_inst->format)
        {
        case TE_INST_FORMAT_0_EXTN:
            break;
        case TE_INST_FORMAT_1_DIFF:
            break;
        case TE_INST_FORMAT_2_ADDR:
            printf("ADDRESS: Address reported: 0x%08X\n\tupdiscon: %d\n", te_inst->address << 1, te_inst->updiscon);
            break;
        case TE_INST_FORMAT_3_SYNC:
        {
            switch (te_inst->subformat)
            {
                
            case TE_INST_SUBFORMAT_START:
                printf("START: Address reported: 0x%08X\n", te_inst->address << 1);
                break;
            case TE_INST_SUBFORMAT_EXCEPTION:
                printf("EXCEPTION: Address reported: 0x%08X\n\tbranch: %d\n\tecause: %d\n\ttvalepc: 0x%08X\n",
                    te_inst->address << 1, te_inst->branch, te_inst->ecause, te_inst->tvalepc);
                break;
            case TE_INST_SUBFORMAT_CONTEXT:
                break;
            case TE_INST_SUBFORMAT_SUPPORT:
                printf("SUPPORT\n");
                break;

            default:
                break;
            }
            break;
        }

        default:
            break;
        }
    printf("\n");
}

int esp_encoder_mode() 
{
    // Open and configure Trace enncoder
    te_encoder_state_t *enc = te_open_trace_encoder(NULL, esp_emit_inst, NULL, NULL);
    assert(enc);
    enc->debug_flags = TE_DEBUG_PC_TRANSITIONS | TE_DEBUG_IMPLICIT_RETURN | TE_DEBUG_FOLLOW_PATH | TE_DEBUG_PACKETS | TE_DEBUG_JUMP_TARGET_CACHE | TE_DEBUG_BRANCH_PREDICTION | TE_DEBUG_EXCEPTIONS;
    enc->debug_stream = stdout;       // Debug output to stdout
    enc->options.full_address = true; // Specific to Espressif. All reported addresses are absolute

    // Send data to encoder
    te_instruction_record_t regular_instruction = {
        .pc = 0x3FF00000,
        .is_qualified = true
    };
    te_encode_one_irecord(enc, &regular_instruction);
    regular_instruction.pc +=4;
    te_encode_one_irecord(enc, &regular_instruction);
    regular_instruction.pc +=4;

    // This is cycle 0 in Bhanu Negi's table
    regular_instruction.is_updiscon = true;
    te_encode_one_irecord(enc, &regular_instruction);
    regular_instruction.is_updiscon = false;
    regular_instruction.pc +=4;

    // This is cycle 1
    regular_instruction.exception_cause = 1, // instruction access fault (see table 3.6 in riscv-priviledged-v1.10.pdf)
    regular_instruction.tval = 0x8FFF0000, // Non-exectuable address
    te_encode_one_irecord(enc, &regular_instruction);
    regular_instruction.pc +=4;

    // An exception has occurred!!
    te_instruction_record_t jalr_to_invalid_address_instruction = {
        .pc = (regular_instruction.pc),
        .is_exception = true,
        .is_qualified = true
    };
    te_encode_one_irecord(enc, &jalr_to_invalid_address_instruction);

    // This is cycle 2
    regular_instruction.pc = 0x2FF00000; // Exception handler
    te_encode_one_irecord(enc, &regular_instruction);
    regular_instruction.pc +=4;

    // Dummy instruction in exception handler +4
    te_encode_one_irecord(enc, &regular_instruction);
    regular_instruction.pc +=4;

    // Unqualified instruction in exception handler = end of trace
    regular_instruction.is_qualified = false;
    te_encode_one_irecord(enc, &regular_instruction);

    free(enc);
}