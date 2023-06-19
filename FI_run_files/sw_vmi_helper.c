#include <config.h>
#include <libvmi/libvmi.h>
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <byteswap.h>

unsigned char memory[10];
vmi_instance_t vmi = NULL;

/*
		printf("res %llX mem %s\n",__bswap_32(res), memory); 

*/

unsigned long long parse_mem_to_int(unsigned char * mem, int n_bytes)
{
	unsigned long long res = 0;
	for (int i = 0; i < n_bytes; i++) {
		res = res << 8;
		res += mem[i];
	}
	return __bswap_64(res);
	//return (res);
}

unsigned long syms_virt_to_phys(unsigned long virt)
{
	if (virt == 0) return virt;
	//return virt - 0xffff82cf91000000;
	return virt - 0xffff82cf90e00000;
}

int
main(
    int argc,
    char **argv)
{
    vmi_mode_t mode;

    /* this is the VM or file that we are looking at */
    char *name = argv[1];

    if (argc != 4) {
	printf("Wrong parameter number\n");
	return -1;
    }

    //addr_t address = syms_virt_to_phys(0xffff82d08052c2a8);
    addr_t address = 0;
	sscanf(argv[3], "%llu", &address);
	address = syms_virt_to_phys(address);
//address=0xEF6042A0;
//	printf("%llu\n", address);

    if (VMI_FAILURE == vmi_get_access_mode(vmi, (void*)name, VMI_INIT_DOMAINNAME, NULL, &mode) ) {
	printf("Wut\n");
        goto error_exit;
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, (void*)name, VMI_INIT_DOMAINNAME, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
    }
	memset(memory, 0, 8);
	vmi_pause_vm(vmi);
	if (strcmp(argv[2], "read_injtsc") == 0) {
		if (VMI_SUCCESS == vmi_read_pa(vmi, address, sizeof(unsigned long long), memory, NULL)) {
			unsigned long long tsc = parse_mem_to_int(memory, sizeof(unsigned long long));
			printf("%llu\n", tsc);
		}
	} else if (strcmp(argv[2], "read_itersafter") == 0) {
		if (VMI_SUCCESS == vmi_read_pa(vmi, address, sizeof(unsigned long), memory, NULL)) {
                        unsigned long iters_after = parse_mem_to_int(memory, sizeof(unsigned long));
                	printf("%lu\n", iters_after);
		}
	} else if (strcmp(argv[2], "read_itersbefore") == 0) {
                if (VMI_SUCCESS == vmi_read_pa(vmi, address, sizeof(unsigned long), memory, NULL)) {
                        unsigned long iters_before = parse_mem_to_int(memory, sizeof(unsigned long));
                        printf("%lu\n", iters_before);
                }
        } else if (strcmp(argv[2], "set_fi_enabled") == 0) {
		unsigned char yes = 1;
        	vmi_write_pa(vmi, address, sizeof(unsigned char), (void *) &yes, NULL); 
	} else {
		printf("Unknown operation\n");
	}

	vmi_resume_vm(vmi);

error_exit:

    /* cleanup any memory associated with the libvmi instance */
    vmi_destroy(vmi);
    return 0;
}
