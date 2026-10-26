// bpf_shim.c — exposes BPF ioctl constants and helpers to Swift.
// The _IOW/_IOR macros behind BIOCSETIF etc. aren't available in the
// SPM C module compilation context, so we define them here in C where
// the system headers are fully available.

#include "include/bpf_shim.h"
