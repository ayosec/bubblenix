/* Generate a BPF program with libseccomp.
 *
 * The rules are inspired by many other programs. Some examples:
 *
 * - https://github.com/flatpak/flatpak/blob/1.15.6/common/flatpak-run.c#L1788
 * - https://github.com/igo95862/bubblejail/blob/0.8.2/src/bubblejail/services.py#L231
 * - https://github.com/systemd/systemd/blob/v255/src/nspawn/nspawn-seccomp.c
 */

#include "options.h"

#include <errno.h>
#include <sched.h>
#include <seccomp.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>


#define TRY(expr)                          \
  do {                                     \
    sc_ret = (expr);                       \
    if (sc_ret != 0) {                     \
      fprintf(                             \
          stderr, "[%s:%d] seccomp: %s\n", \
          __FILE__, __LINE__,              \
          strerror(-sc_ret));              \
      goto finish;                         \
    }                                      \
  } while(0)


#define ADD0(syscall, errno)   \
  TRY(seccomp_rule_add(        \
        seccomp,               \
        SCMP_ACT_ERRNO(errno), \
        SCMP_SYS(syscall),     \
        0                      \
  ))


#define ADD1(syscall, errno, arg) \
  TRY(seccomp_rule_add(           \
        seccomp,                  \
        SCMP_ACT_ERRNO(errno),    \
        SCMP_SYS(syscall),        \
        1,                        \
        arg                       \
  ))


bool generate_bpf(struct Options *options) {
  int sc_ret = 0;

  scmp_filter_ctx seccomp = seccomp_init(SCMP_ACT_ALLOW);

  ADD0(acct, EPERM);
  ADD0(quotactl, EPERM);
  ADD0(reboot, EPERM);
  ADD0(syslog, EPERM);
  ADD0(uselib, EPERM);

  ADD0(switch_endian, EPERM);
  ADD0(vm86, EPERM);
  ADD0(vm86old, EPERM);

  ADD0(add_key, EPERM);
  ADD0(keyctl, EPERM);
  ADD0(request_key, EPERM);

  ADD0(swapoff, EPERM);
  ADD0(swapon, EPERM);

  ADD0(get_mempolicy, EPERM);
  ADD0(mbind, EPERM);
  ADD0(migrate_pages, EPERM);
  ADD0(move_pages, EPERM);
  ADD0(set_mempolicy, EPERM);

  ADD0(chroot, EPERM);
  ADD0(mount, EPERM);
  ADD0(pivot_root, EPERM);
  ADD0(setns, EPERM);
  ADD0(umount, EPERM);
  ADD0(umount2, EPERM);
  ADD0(unshare, EPERM);

  ADD0(fsconfig, ENOSYS);
  ADD0(fsmount, ENOSYS);
  ADD0(fsopen, ENOSYS);
  ADD0(fspick, ENOSYS);
  ADD0(mount_setattr, ENOSYS);
  ADD0(move_mount, ENOSYS);
  ADD0(open_tree, ENOSYS);

  ADD0(create_module, EPERM);
  ADD0(delete_module, EPERM);
  ADD0(finit_module, EPERM);
  ADD0(init_module, EPERM);
  ADD0(query_module, EPERM);

  ADD1(clone, EPERM, &SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER));

  ADD1(ioctl, EPERM, &SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFFFFFFFFu, (int)TIOCLINUX));
  ADD1(ioctl, EPERM, &SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFFFFFFFFu, (int)TIOCSTI));

  if (!options->allow_clone3) {
    ADD0(clone3, ENOSYS);
  }

  if (!options->allow_fsync) {
    ADD0(fdatasync, 0);
    ADD0(fsync, 0);
    ADD0(sync, 0);
    ADD0(sync_file_range, 0);
  };

  if (!options->allow_tracing) {
    ADD0(bpf, EPERM);
    ADD0(perf_event_open, EPERM);
    ADD0(personality, EPERM);
    ADD0(process_vm_readv, EPERM);
    ADD0(process_vm_writev, EPERM);
    ADD0(ptrace, EPERM);
  };

  TRY(seccomp_export_bpf(seccomp, fileno(options->output)));

finish:
  fclose(options->output);
  seccomp_release(seccomp);

  return sc_ret == 0;
}
