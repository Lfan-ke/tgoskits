INCLUDE "runtime.x"

PROVIDE(_ex_table_start = 0);
PROVIDE(_ex_table_end = 0);

SECTIONS {
    .static_keys : {
        __start___static_keys = .;
        KEEP(*(__static_keys))
        __stop___static_keys = .;
    }

    .dyndbg : {
        __start___dyndbg = .;
        KEEP(*(__dyndbg))
        __stop___dyndbg = .;
    }

    .tracepoint : {
        __start_tracepoint = .;
        KEEP(*(.tracepoint .tracepoint.*))
        __stop_tracepoint = .;
    }

    .kmod_export : {
        __start_kmod_export = .;
        KEEP(*(.kmod_export .kmod_export.*))
        __stop_kmod_export = .;
    }

    abi_register : {
        __start_abi_register = .;
        KEEP(*(abi_register))
        __stop_abi_register = .;
    }

    binfmt_register : {
        __start_binfmt_register = .;
        KEEP(*(binfmt_register))
        __stop_binfmt_register = .;
    }

    custom_register : {
        __start_custom_register = .;
        KEEP(*(custom_register))
        __stop_custom_register = .;
    }

    .kallsyms : ALIGN(4K) {
        __kallsyms_start = .;
        . += 8M; /* reserve space for kallsyms, can be recycled */
        __kallsyms_end = .;
    }
}

INSERT AFTER .data;
