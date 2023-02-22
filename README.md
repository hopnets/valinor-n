## Summary

* Name: vswitch (Valinor-N traffic measurement framework based on Tofino architecture)
* P4 version: P4_16
* Architectures: Tofino Native Architecture (TNA)

This program clones the packets sourced from specific IP addresses and appends a metadata header containing various arrival timestamps, queueing info, and original packet lengths. The metadata packets are sent to a user-defined port for offline processing.

More information can be found at [in our NSDI paper](https://www.usenix.org/conference/nsdi23/presentation/sharafzadeh).

Also checkout [Valinor super repository](https://github.com/hopnets/valinor-artifacts).

Refer to the bfrt sources in `cp` directory for configuring Valinor-N.

## Author
Erfan Sharafzadeh

2020-2023
