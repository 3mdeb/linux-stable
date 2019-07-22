#!/bin/bash -x
ssh root@${1} "mount /dev/sda1 /mnt"
scp arch/x86/boot/bzImage root@${1}:/mnt/boot/bzImage
sha256sum arch/x86/boot/bzImage
ssh root@${1} "sha256sum /mnt/boot/bzImage"
ssh root@${1} "umount /dev/sda1 && poweroff"
