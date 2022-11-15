.. SPDX-License-Identifier: GPL-2.0

=============
Scheduler QoS
=============

sched_setattr(2) and sched_getattr(2) pass sched_attr.sched_qos_hints
between user and kernel.

These hints are stored task_struct.qos_hints, which persists across fork,
but is cleared on exec.

The default value for these hints is zero.

Linux may enable generic, arch-specific, or model-specific
optimizations based on these QOS hints,
depending on the available hardware.
