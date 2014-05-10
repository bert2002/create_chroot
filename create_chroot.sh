#!/bin/bash
# script: create chroot environment with bandwith limitation
# author: Steffen Wirth <s.wirth@itbert.de>

###
# Information and pre stuff
###

USERPREFIX="u"
SSHGROUP="sshusers"
JAILBASE="/var/jail"
DISKBASE="/var/jail/disk"
SCRIPTBASE="/var/jail/scripts"

APPLICATIONS="/bin/bash /bin/cp /usr/bin/dircolors /bin/ls /bin/mkdir /bin/mv /bin/rm /bin/rmdir /bin/sh /usr/bin/groups /usr/bin/id /usr/bin/ssh /usr/bin/scp /usr/bin/telnet /bin/ping /bin/nc /usr/bin/wget /usr/bin/host /usr/bin/vi /usr/bin/less /bin/cat /usr/bin/diff /usr/bin/curl /bin/grep /usr/sbin/traceroute"

OTHERLIBFILES="libnss_compat.so.2 libnsl.so.1 libnss_files.so.2 libcap.so.2 libnss_dns.so.2 ld-linux*.so.2"
CREATEUSER="0" # to check if user already exist. must be set to zero

IF=eth0
DNLD=1kbps

###
# Script
###

function __usage {
	echo "Usage: $0 {create_user|delete_user|init_server|remove_tc|show_tc} {userid}"
	echo ""
	exit 1
}

function __init_server {

	echo -n "do you want to initialize the server? [y/N] "
	read bla 
	if [ $bla != "y" ]; then exit 1 ; fi

	# notes
	mkdir -p $JAILBASE $DISKBASE $SCRIPTBASE
	groupadd $SSHGROUP
	cp $0 $SCRIPTBASE/

	aptitude -q -y update && aptitude -y install debianutils coreutils traceroute mtr curl pwgen netcat-openbsd

	echo "" >> /etc/ssh/sshd_config
	echo "Match group $SSHGROUP" >> /etc/ssh/sshd_config
	echo "ChrootDirectory $JAILBASE/%u/" >> /etc/ssh/sshd_config
  echo "X11Forwarding no" >> /etc/ssh/sshd_config
  echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
	echo ""
	/etc/init.d/ssh restart >/dev/null 2>&1

	# create nice /etc/motd
	echo "" 						> /etc/motd
	echo "# --------------- #" 				>> /etc/motd
	echo "#      SHELL      #" 				>> /etc/motd
	echo "" 						>> /etc/motd
	echo "Rules:" 						>> /etc/motd
	echo "1. Only test your own systems" 			>> /etc/motd
	echo "2. Do not do _anything_ that is illegal" 		>> /etc/motd
	echo "" 						>> /etc/motd
	echo "Programs:" 					>> /etc/motd
	echo "bash, sh, cp, ls, mkdir, etc..." 			>> /etc/motd
	echo "" 						>> /etc/motd
	echo "Outgoing:" 					>> /etc/motd
	echo "IP: " 						>> /etc/motd

	# update limits.conf
	echo "### for chroot user" 				>> /etc/security/limits.conf
	echo "@$SSHGROUP       hard    memlock         10240" 	>> /etc/security/limits.conf
	echo "@$SSHGROUP       hard    nofile          128" 	>> /etc/security/limits.conf
	echo "@$SSHGROUP       hard    stack           1024" 	>> /etc/security/limits.conf
	echo "@$SSHGROUP       hard    nproc           5" 	>> /etc/security/limits.conf
	echo "@$SSHGROUP       hard    as              64000" 	>> /etc/security/limits.conf
	echo "@$SSHGROUP       hard    priority        20" 	>> /etc/security/limits.conf
	echo "@$SSHGROUP       hard    nice            20" 	>> /etc/security/limits.conf

	# add su restrictions for group
	echo "auth       required   pam_wheel.so deny group=$SSHGROUP" >> /etc/pam.d/su

	# add remove user on startup
	cat /etc/rc.local | grep -v "^exit" > /etc/rc.local && chmod +x /etc/rc.local
	echo "$SCRIPTBASE/$0 delete_user all" >> /etc/rc.local

}

function __create_user {

	# check if user already exist
	while [ $CREATEUSER != "1" ]; do
		NEWRAND=$[ ( $RANDOM$RANDOM % ( $[ 9999999 - 1 ] + 1 ) ) + 1 ]
		NEWUSER=${USERPREFIX}${NEWRAND}

		TEMP=`id $NEWUSER >/dev/null 2>&1`
		if [ $? != "0" ]; then
			CREATEUSER="1"
			echo "user $NEWUSER does not exist. wohoo"
		fi
	done

	# create user
	JAILDIR="$JAILBASE/$NEWUSER"
	HOMEDIR="/home/$NEWUSER"
	SHELL="/bin/bash"
	NEWPASSWORD=`pwgen -y -c -n -c -N 1 12`
	SALTED=$(perl -e 'print crypt($ARGV[0], "password")' $NEWPASSWORD)

	mkdir -p $JAILDIR/$HOMEDIR
	useradd -g $SSHGROUP -s $SHELL -d $HOMEDIR -m $NEWUSER --password $SALTED >/dev/null 2>&1
	if [ $? == "0" ]; then
		echo "user created"

		# create jail
		mkdir -p $JAILDIR/{dev,etc,lib,lib64,usr,bin}
		mkdir -p $JAILDIR/usr/bin
		chown root.root $JAILDIR

		# create dev stuff
		mknod $JAILDIR/dev/urandom c 1 9
		mknod -m 666 $JAILDIR/dev/null c 1 3
		mknod -m 666 $JAILDIR/dev/zero c 1 5
		mknod -m 666 $JAILDIR/dev/tty c 5 0 
	
		# create necessary files
		echo "nameserver 8.8.8.8" > 		$JAILDIR/etc/resolv.conf
		echo "nameserver 8.8.4.4" >> 		$JAILDIR/etc/resolv.conf
		echo "nameserver 208.67.222.222" >> $JAILDIR/etc/resolv.conf
		echo "nameserver 208.67.220.220" >> $JAILDIR/etc/resolv.conf

		echo "127.0.0.1    localhost" > 	$JAILDIR/etc/hosts

		# etc	
		cp /etc/ld.so.cache	$JAILDIR/etc/
		cp /etc/ld.so.conf	$JAILDIR/etc/
		cp /etc/nsswitch.conf	$JAILDIR/etc/

		grep /etc/passwd -e "^root" > 		$JAILDIR/etc/passwd
    grep /etc/group -e "^root" >        $JAILDIR/etc/group
		grep /etc/passwd -e "^$NEWUSER" >> 	$JAILDIR/etc/passwd
		grep /etc/group -e "^$NEWUSER" >> 	$JAILDIR/etc/group
		grep /etc/shadow -e "^$NEWUSER" > 	$JAILDIR/etc/shadow

		# bin
		for APP in $APPLICATIONS ; do

			APPBASE=`dirname $APP`
			if [ ! -d "$JAILDIR$APPBASE" ]; then
				mkdir -p $JAILDIR$APPBASE
			fi
		
			cp $APP $JAILDIR$APPBASE
			if [ $? != "0" ]; then
				echo "copy $APP failed"
				exit 1
			fi
		
			# copy ldd of binaries
			LDDFILES=`ldd $APP | awk '{ print $3 }' |egrep -v ^'\('`

			for FILE in $LDDFILES ; do

				LDDBASE=`dirname $FILE`
				if [ ! -d "$JAILDIR$LDDBASE" ]; then
					mkdir -p $JAILDIR$LDDBASE
				fi

				cp $FILE $JAILDIR$LDDBASE
				if [ $? != "0" ]; then
					echo "copy $FILE failed"
					exit 1
				fi
			

			done

		done
		

		# copy other necessary files
		for OTHERLIB in $OTHERLIBFILES ; do 

			cp /lib/$OTHERLIB $JAILDIR/lib/	

			if [ `uname -m` == "x86_64" ]; then
				cp /lib64/$OTHERLIB $JAILDIR/lib64/
			fi
		done 

		# fix file permissions
		chmod u+s $JAILDIR/bin/ping	

		# create disk image if not available 
		if [ ! -f "$DISKBASE/template.img" ]; then
			dd if=/dev/zero of=$DISKBASE/template.img count=40960 >/dev/null 2>&1
			mkfs -t ext3 -q $DISKBASE/template.img -F >/dev/null 2>&1
			if [ $? == "0" ]; then
				echo "created new template image"
			else
				echo "creating new template image failed"
				exit 1
			fi
		fi

		# copy disk image to new user
		cp $DISKBASE/template.img $DISKBASE/$NEWUSER.img
		if [ $? == "0" ]; then
			echo "copied disk image"
			mount -o rw,loop -t ext3 $DISKBASE/$NEWUSER.img $JAILDIR/$HOMEDIR >/dev/null 2>&1
			if [ $? == "0" ]; then
				echo "mounting virtual home disk"
				chown -R $NEWUSER $JAILDIR/$HOMEDIR >/dev/null 2>&1
				if [ $? == "0" ]; then
					echo "fixing permissions in home directory"
				else
					echo "fixing permissions in home directory failed"
					exit 1
				fi
			else
				echo "mounting disk failed"
				$0 delete_user $NEWUSER
				test -f $DISKBASE/$NEWUSER.img && rm -rf $DISKBASE/$NEWUSER.img && echo "removed disk file"
				modprobe loop && echo "try again. loaded loop kernel modul"
				exit 1
			fi
		else
			echo "creating disk image failed"
			exit 1
		fi

		# configure traffic shapping snip snap
		NEWUSERID=$(id -u $NEWUSER)
    iptables -t mangle -A OUTPUT -m owner --uid-owner $NEWUSER -j MARK --set-mark $NEWUSERID
		
		tc qdisc add dev $IF root handle 1: htb default 30 >/dev/null 2>&1
		tc class add dev $IF parent 1: classid 1:1 htb rate $DNLD >/dev/null 2>&1
		tc filter add dev $IF protocol ip parent 1:0 prio 1 handle $NEWUSERID fw flowid 1:1 >/dev/null 2>&1
		if [ $? == "0" ]; then
			echo "traffic shaping activated for user"
		fi
		
		# final print
		echo "user credentials"
		echo "username: $NEWUSER"
		echo "password: $NEWPASSWORD"

	else
		echo "creating user failed"
		exit 1
	fi

}


function __delete_user {

	if [ $USERID == "all" ]; then
		USERID=`grep ^$USERPREFIX[0-9]. /etc/passwd | awk -F':' '{print $1}'`
	fi

	for MYUSER in $USERID ; do 

		echo "usage: delete_user $MYUSER"

		# delete all running process from user
		pkill -9 -u $MYUSER >/dev/null 2>&1
		echo "killed all user process"

		# umount disk
		umount -f $JAILBASE/$MYUSER/home/$MYUSER >/dev/null 2>&1
		if [ $? == "0" ]; then
			echo "unmounted virtual disk image"
		else
			echo "unmounting virtual disk image was tricky"
		fi
		test -f $DISKBASE/$MYUSER.img && rm -rf $DISKBASE/$MYUSER.img && echo "removed disk file"       


		# delete user
		deluser -q $MYUSER
		if [ $? == "0" ]; then
			echo "user $MYUSER deleted"
		
			cd $JAILBASE && rm -rf $MYUSER
			if [ $? == "0" ]; then
				echo "removed $JAILBASE/$MYUSER"
			else
				echo "removing $JAILBASE/$MYUSER failed"
				exit 1
			fi
		else
			echo "deleting $MYUSER failed"
			exit 1
		fi
	done
}


function __remove_tc {
	echo -n "Stopping bandwidth shaping: "
	tc qdisc del dev $IF root	
	echo "done"
}

function __show_tc {
	echo "Bandwidth shaping status for $IF:"
	tc -s qdisc ls dev $IF
	echo ""
}

###
# logic
###

if [ -z $1 ]; then 
	__usage 
else
	if [ $1 == "create_user" ]; then
			__create_user
	elif [ $1 == "delete_user" ]; then
		if [ -n "$2" ]; then
			USERID="$2"
			__delete_user
		else
			echo "userid is not configured."
			exit 1
		fi
	elif [ $1 == "init_server" ]; then
		__init_server
	elif [ $1 == "remove_tc" ]; then
		__remove_tc
        elif [ $1 == "show_tc" ]; then
		__show_tc
	else
		__usage
	fi
fi

