# CVE-2019-2215
PoC for old Binder vulnerability (based on P0 exploit)

# Description
A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application

# Reference
- https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html
- https://cloudfuzz.github.io/android-kernel-exploitation/

# Note
This is only a PoC and no shell is spawned. It's only purpose is for learning kernel exploitation. Indeed, the expected result is to have a modified `addr_limit` in task_struct.
