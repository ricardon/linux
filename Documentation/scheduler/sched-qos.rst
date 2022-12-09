.. SPDX-License-Identifier: GPL-2.0

=============
Scheduler QoS
=============

sched_setattr(2) and sched_getattr(2) pass sched_attr.sched_qos_hints
between user and kernel.

These hints are stored task_struct.qos_hints, which persists across fork,
but is cleared on exec.

The default value for these hints is zero.

The bottom 4-bits of qos_hints denotes Energy Quality of Service:

``EQOS_MAX_PERFORMANCE`` prefer performance over energy efficiency.

``EQOS_BALANCE_PERFORMANCE`` balance performance and energy efficiency,
with a bias towards performance.

``EQOS_BALANCE_EFFICIENCY`` balance performance and energy efficiency
with a bias towards energy efficiency.

``EQOS_MAX_EFFICIENCY`` prefer energy efficiency over performance.

``EQOS_DEFAULT`` (0), use system default.

Upper bits are reserved for future use.

Linux may enable generic, arch-specific, or model-specific
optimizations based on these QOS hints,
depending on the available hardware.
