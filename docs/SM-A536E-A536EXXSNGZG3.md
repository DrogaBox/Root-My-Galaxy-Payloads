# SM-A536E / A536EXXSNGZG3 port record

## Status

```text
model: SM-A536E
device: a53x
region/CSC: ARO / OWO
AP/PDA: A536EXXSNGZG3
CP: CP35408712
display build: TP1A.220624.014
system fingerprint: samsung/a53xeea/a53x:13/TP1A.220624.014/A536EXXSNGZG3:user/release-keys
Android SDK: 33
ABI: arm64-v8a
page size: 4096
kernel release: 5.10.237-android12-9-31999025-abA536EXXSNGZG3
```

The exploit profile, app payload, Samsung-compatible KernelSU module, and
late-load binary are static-analysis and build verified. There was no target
handset, so execution remains device-untested.

No values in this profile were copied from the 6.1 or 6.6 targets. The 5.10
layout follows the A155N legacy `rt_mutex_waiter` path
([`SM-A155N-A155NKSS6BYH1.md`](SM-A155N-A155NKSS6BYH1.md)) with target-exact
offsets derived from the A536EXXSNGZG3 Image.

## Firmware extraction

Firmware was downloaded from Samsung FUS (region ARO/OWO):

```text
SM-A536E_5_20260715000021_5v34nx129x_fac.zip.enc4   (8.50 GB)
```

The AP archive contains:

```text
AP_A536EXXSNGZG3_A536EXXSNGZG3_MQB112076572_REV00_user_low_ship_MULTI_CERT_meta_OS16.tar.md5
BL_A536EXXSNGZG3_A536EXXSNGZG3_MQB112076572_REV00_user_low_ship_MULTI_CERT.tar.md5
CP_A536EXXSNGZG3_CP35408712_MQB112076572_REV00_user_low_ship_MULTI_CERT.tar.md5
CSC_OWO_A536EOWONGZG3_QB112089493_REV00_user_low_ship_MULTI_CERT.tar.md5
HOME_CSC_OWO_A536EOWONGZG3_QB112089493_REV00_user_low_ship_MULTI_CERT.tar.md5
```

`boot.img.lz4` was decompressed (Samsung LZ4 frame) to recover the raw ARM64
`Image`. The Android boot image uses header version 4 with a 4096-byte page;
the kernel payload starts at `0x1000`. The retained raw kernel is:

```text
artifacts/kernel-Image-arm64-5.10.237-android12-9.bin
```

The recovered `vmlinux_5.10.237.elf` reports 113,780 symbols at base
`0xffffffc008000000` (`vmlinux-to-elf`). The target contains IKCONFIG but no
BTF. The exact config was retained as `artifacts/ikconfig.config` and includes
`CONFIG_TRIM_UNUSED_KSYMS=y` and `CONFIG_ARM64_VA_BITS_39=y`.

The embedded banner vermagic:

```text
5.10.237-android12-9-31999025-abA536EXXSNGZG3 SMP preempt mod_unload modversions aarch64
```

## Required target offsets

All values were derived from and validated against the target Image
(`artifacts/target.h`):

| Use | Target symbol/derivation | Offset |
| --- | --- | ---: |
| UMH callback | `call_usermodehelper_exec_work` | `0x000f6be4` |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | instruction after the blocking `worker_thread -> schedule` call | `0x000fe2f8` |
| `NOOP_LLSEEK_OFF` | `noop_llseek` | `0x003789dc` |
| `COPY_SPLICE_READ_OFF` | `generic_file_splice_read` | `0x003c3ad8` |
| configfs read | `configfs_read_iter` | `0x00447488` |
| configfs write | `configfs_bin_write_iter` | `0x004478e8` |
| ashmem ioctl | `ashmem_ioctl` | `0x00c378e8` |
| ashmem compat ioctl | `compat_ashmem_ioctl` | `0x00c3823c` |
| ashmem mmap | `ashmem_mmap` | `0x00c38294` |
| ashmem open | `ashmem_open` | `0x00c384c4` |
| ashmem release | `ashmem_release` | `0x00c38548` |
| ashmem fdinfo | `ashmem_show_fdinfo` | `0x00c38668` |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | `"nfnetlink_log"` string referenced by `nfulnl_logger.name` | `0x0188af33` |
| pipe ops | `anon_pipe_buf_ops` | `0x0197b2e8` |
| ashmem fops | `ashmem_fops` | `0x01b06f18` |
| kmalloc table | `kmalloc_caches` | `0x01b4c9c0` |
| system workqueue | `system_unbound_wq` | `0x01df9e10` |
| init task | `init_task` | `0x01e0dd00` |
| `SLIDE_NFULNL_LOGGER_OBJECT_OFF` | `nfulnl_logger` object | `0x01e01370` |
| ashmem misc fops | `ashmem_misc + 0x10` | `0x01ffbc20` |
| `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` | `.data` pointer slot in the `random_table[]` entry named `boot_id` | `0x01fbc430` |
| root task group | `root_task_group` | `0x02082080` |
| SELinux enforcing | `selinux_state.enforcing` | `0x021ddb6a` |
| `SLIDE_SYSCTL_BOOTID_OFF` | actual `sysctl_bootid` UUID storage | `0x02282109` |

`__TRACE_LAST_TYPE` is 17 on this branch. `sched_blocked_reason` has
zero-based linker registration index 87, so the target event ID is
`17 + 87 = 104`. `SLIDE_PSELECT_WORD_SHIFT` is zero. `SLIDE_MAX_ATTEMPTS` is 32
and the physical P0 oracle is enabled in the app payload
(`APP_PHYS_P0_ORACLE 1`, 4 bank slots).

## Physical map

```c
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END  0xffffffc000000000ULL
#define VMEMMAP_START    0xfffffffeffe00000ULL
```

## 5.10 layout changes

The target uses the legacy 0x50-byte waiter layout
(`LEGACY_RT_MUTEX_WAITER=1`), identical to the A15 5.10 port:

```text
mm_struct cache object: 0x3c0
mm_struct slab order: 3

rt_mutex_waiter.pi_tree_entry: 0x18
rt_mutex_waiter.task: 0x30
rt_mutex_waiter.lock: 0x38
rt_mutex_waiter.prio: 0x40
rt_mutex_waiter.deadline: 0x48
sizeof(rt_mutex_waiter): 0x50

task_struct.usage: 0x40
task_struct.prio: 0x84
task_struct.normal_prio: 0x8c
task_struct.sched_task_group: 0x310
task_struct.pi_lock: 0x86c
task_struct.pi_waiters: 0x880
task_struct.pi_top_task: 0x890
task_struct.pi_blocked_on: 0x898

workqueue_struct.dfl_pwq: 0xb0
pool_workqueue.nr_active: 0x58
pool_workqueue.max_active: 0x5c
worker_pool.worklist: 0x20
worker_pool.nr_idle: 0x34
```

Accounted pipe-buffer allocations use the normal `kmalloc-2k` cache
(`KMALLOC_CGROUP_TYPE 0`, `KMALLOC_CACHE_TYPES 2`).

## P0 table and build

`artifacts/p0_fingerprint.h` contains 32 slide rows generated from this
target Image (8 qwords at page offsets `0x000, 0x200, ..., 0xe00`, slides
`0x000000` through `0x1f0000`) and verified against `artifacts/abi_symbollist.raw`.

The release payload is `artifacts/exploit/cve-2026-43499-app.release.so`
(104,128 bytes, the fixed app-required size), published as
`artifacts/a53-A536EXXSNGZG3/cve-2026-43499-app.so`:

| File | Size | SHA-256 |
| --- | ---: | --- |
| `artifacts/a53-A536EXXSNGZG3/cve-2026-43499-app.so` | 104,128 | `A5F2D852758328A42E6DD677B91772756DE113F887DBD50DBCAB7A74CC9F1E65` |

## KernelSU 5.10 port

The module was rebuilt from KernelSU commit
`b0bc817b4e966aa6aa830834eaf6ef765d821d40` (v3.2.5) plus the Samsung
KDP/RKP/DEFEX patch (`KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch`), against
the a53x kernel mirror `Gabriel2392/android_kernel_samsung_a53x_xy` branch
`A536BXXSAEXE1` (5.10.198, the closest released mirror to the 5.10.237
target). The top-level Makefile was pinned to
`SUBLEVEL=237`, `EXTRAVERSION=-android12-9-31999025-abA536EXXSNGZG3` and an
empty `.scmversion` suppresses the git suffix, so `kernel.release`/`UTS_RELEASE`
reproduce the exact device release string. Toolchain: Android NDK r27c (Linux,
clang 18.0.3) with `LLVM=1 LLVM_IAS=1`.

The standalone KO reports exactly:

```text
5.10.237-android12-9-31999025-abA536EXXSNGZG3 SMP preempt mod_unload modversions aarch64
```

The target has `CONFIG_TRIM_UNUSED_KSYMS=y`. `ksuinit::load_module()` resolves
all undefined module symbols from `/proc/kallsyms` before `init_module`, so the
KO intentionally retains a zero-length `__versions` section (manual
relocation). The module's 208 undefined symbols were all found in the
recovered target `vmlinux`; `check_symbol` and the full audit report
`missing from target symbol table: 0` and `target CRC mismatches: 0`
(`tools/audit_module_against_target.py --manual-relocation` against the 7,206
CRCs recovered by `tools/extract_target_symvers.py`).

The `ksud` binary embeds that KO as the `android12-5.10_kernelsu.ko` KMI asset.

Release outputs:

| File | Size | SHA-256 |
| --- | ---: | --- |
| `kernelsu/android12-5.10_kernelsu-a53-A536EXXSNGZG3-kdp.ko` | 350,776 | `4B9212EFA29337C5B21B27AF63A17640C760E39C6186CEE2ABA068D6BA20EAC7` |
| `kernelsu/ksud-a53-A536EXXSNGZG3-kdp` | 4,872,960 | `5395A5FAF45CEC60F5593A02B225C95BC9226BD28D93A202B2AD5016F52ED018` |

This exact profile is included in the support feed (`targets-v3.json`,
`payloadId: a53-A536EXXSNGZG3`), but hardware execution remains unverified
until an `SM-A536E` running `A536EXXSNGZG3` is available.

## Build notes (macOS → Linux)

The port kit was prepared on macOS; the module build itself is Linux-only.
Three macOS-specific incompatibilities (no `elf.h`, conflicting `uuid_t`,
BSD `sed` in `headers_install`) do not apply on Linux. Two additional host
issues surfaced and were resolved during the first Linux build:

1. the NDK r27c prebuilt copied from macOS ships Mach-O `linux-x86_64`
   binaries that do not execute on Linux — the Linux NDK r27c must be used;
2. `ksud`'s `bindgen` needs `LIBCLANG_PATH` pointing at a real `libclang`
   (system `libclang-21`), not the NDK lib dir.
