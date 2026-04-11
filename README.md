# BPF-Audit / BPF-Ledger 

kernel–userspace system that records eBPF lifecycle events (load/unload/attach/dettach) into a tamper-evident ledger using eBPF and a custom kernel module.

It streams these events to userspace via a character device, where they are logged, validated, and optionally sent to a remote attestor.

Goal: provide reliable, append-only auditing and detection of eBPF activity at runtime.
