
/**
 * attach_paths.h - Internal initialization interface for BPF attachment paths
 *
 * Declares the initialization and cleanup routines for all supported BPF
 * attachment path subsystems. Each subsystem is responsible for registering
 * and unregistering the probes associated with its attachment mechanism.
 */

int prog__init(void);
void prog__exit(void);

int link_init(void);
void link_exit(void);

int perf_init(void);
void perf_exit(void);

int prog_attach_init(void);
void prog_attach_exit(void);

int setsockopt_init(void);
void setsockopt_exit(void);