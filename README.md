
Create CHROOT environment for Unix user
=============

Easy chroot management for user and bandwidth limitation (awesome!) for each user. Additionally each user gets a writable image file for files, scripts, etc.

Features
-------

* user management
* bandwith limitation
* writable img file for chrooted user

Usage
-------

$ bash create_chroot.sh
Usage: create_chroot.sh {create_user|delete_user|init_server|remove_tc|show_tc} {userid}

Walkthrough
-------
```
$ create_chroot.sh init_server # create directory and install software
$ create_chroot.sh create_user u007 # create user
$ create_chroot.sh delete_user u007 # delete user
$ create_chroot.sh show_tc # show traffic shaping
$ create_chroot.sh remove_tc # remove traffic shaping
```

Known Problems
-------

* Opimized for Ubuntu 12.04


