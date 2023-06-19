#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/stop_machine.h>

MODULE_LICENSE("GPL");

static int hang(void *arg)
{
    while (1) {
        // ciclo infinito para ser chamado no stop_machine()
        printk(KERN_INFO "Hanging...\n");
    }
    return 0;
}

static int __init my_module_init(void)
{
    int ret;
    ret = stop_machine(hang, NULL, NULL);
    if (ret) {
        printk(KERN_INFO "left stop_machine()\n");
        return ret;
    }
    return 0;
}

module_init(my_module_init);
