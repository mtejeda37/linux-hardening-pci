#!/bin/bash
#
#
#########################################################
##### CIS HARDENING SCRIPT FOR PCI-DSS REQUIREMENTS #####
#####		BY MIGUEL TEJEDA - NOV 2019				#####
#####					RHEL 7						#####
#########################################################

### BEGIN HERE ###
> ~/hardening.log
echo "Ejecutando script, iniciar!! - `date` "; sleep 2
echo "Ejecutando script, iniciar!! - `date` " >> ~/hardening.log

#### ensure /tmp nodev,nosuid,noexec is enable ### 
df | grep /tmp
	if [ $? -eq 0 ]
	then
			mount | grep /tmp | grep noexec && mount | grep /tmp | grep nodev && mount | grep /tmp | grep nosuid
		if [ $? -eq 0 ]
			then
				echo "1.1.2 Ensure separate partition exists for /tmp OK" >> ~/hardening.log
				echo "1.1.3 Ensure nodev option set on /tmp partition OK"  >> ~/hardening.log
				echo "1.1.4 Ensure nosuid option set on /tmp partition OK" >> ~/hardening.log
				echo "1.1.5 Ensure noexec option set on /tmp partition OK" >> ~/hardening.log
			else 
				echo "[Mount] 
Options=mode=1777,strictatime,noexec,nodev,nosuid" >> /etc/systemd/system/local-fs.target.wants/tmp.mount
				echo "1.1.2 Ensure separate partition exists for /tmp OK" >> ~/hardening.log
				echo "1.1.3 Ensure nodev option set on /tmp partition OK"  >> ~/hardening.log
				echo "1.1.4 Ensure nosuid option set on /tmp partition OK" >> ~/hardening.log
				echo "1.1.5 Ensure noexec option set on /tmp partition OK" >> ~/hardening.log
			fi
	else
				echo "1.1.2 Ensure separate partition exists for /tmp OK" >> ~/hardening.log
				echo "1.1.3 Ensure nodev option set on /tmp partition OK"  >> ~/hardening.log
				echo "1.1.4 Ensure nosuid option set on /tmp partition OK" >> ~/hardening.log
				echo "1.1.5 Ensure noexec option set on /tmp partition OK" >> ~/hardening.log
	fi

echo "1.1.6 Ensure separate partition exists for /var NO APLICA" >> ~/hardening.log

#### ensure /var/tmp nodev,nosuid,noexec is enable ### 

df | grep /var/tmp
	if [ $? -eq 0 ]
	then
			mount | grep /var/tmp | grep noexec && mount | grep /var/tmp | grep nodev && mount | grep /var/tmp | grep nosuid
		if [ $? -eq 0 ]
			then
				echo "1.1.7 Ensure separate partition exists for /var/tmp OK" >> ~/hardening.log
				echo "1.1.8 Ensure nodev option set on /var/tmp partition OK" >> ~/hardening.log
				echo "1.1.9 Ensure nosuid option set on /var/tmp partition OK" >> ~/hardening.log
				echo "1.1.10 Ensure noexec option set on /var/tmp partition OK" >> ~/hardening.log
			else
				echo "tmpfs /var/tmp tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
				echo "1.1.7 Ensure separate partition exists for /var/tmp OK" >> ~/hardening.log
				echo "1.1.8 Ensure nodev option set on /var/tmp partition OK" >> ~/hardening.log
				echo "1.1.9 Ensure nosuid option set on /var/tmp partition OK" >> ~/hardening.log
				echo "1.1.10 Ensure noexec option set on /var/tmp partition OK" >> ~/hardening.log
			fi
	else
				echo "1.1.7 Ensure separate partition exists for /var/tmp OK" >> ~/hardening.log
				echo "1.1.8 Ensure nodev option set on /var/tmp partition OK" >> ~/hardening.log
				echo "1.1.9 Ensure nosuid option set on /var/tmp partition OK" >> ~/hardening.log
				echo "1.1.10 Ensure noexec option set on /var/tmp partition OK" >> ~/hardening.log
	fi


echo "1.1.11 Ensure separate partition exists for /var/log NO APLICA" >> ~/hardening.log
echo "1.1.12 Ensure separate partition exists for /var/log/audit NO APLICA" >> ~/hardening.log

#### ensure /home nodev is enable ### 

df | grep /home
	if [ $? -eq 0 ]
	then
		mount | grep /home | grep nodev
		if [ $? -eq 0 ]
			then
				echo "1.1.13 Ensure separate partition exists for /home OK">> ~/hardening.log
				echo "1.1.14 Ensure nodev option set on /home partition OK">> ~/hardening.log
			else
				fs1=$(df -Th | grep /home | tr -s " "| cut -d" " -f1)
				fs2=$(df -Th | grep /home | tr -s " "| cut -d" " -f2)
				sed -i '/home /d' /etc/fstab
				echo "$fs1 /home $fs2 defaults,nodev 0 0" >> /etc/fstab
				echo "1.1.13 Ensure separate partition exists for /home OK">> ~/hardening.log
				echo "1.1.14 Ensure nodev option set on /home partition OK">> ~/hardening.log
			fi
	else
				echo "1.1.13 Ensure separate partition exists for /home OK">> ~/hardening.log
				echo "1.1.14 Ensure nodev option set on /home partition OK">> ~/hardening.log
	fi


#### ensure /dev/shm nodev,nosuid,noexec is enable ### 
df | grep /dev/shm
	if [ $? -eq 0 ]
	then
		mount | grep /dev/shm | grep noexec && mount | grep /dev/shm | grep nodev && mount | grep /dev/shm | grep nosuid
		if [ $? -eq 0 ]
			then
				echo "1.1.15 Ensure nodev option set on /dev/shm partition OK">> ~/hardening.log
				echo "1.1.16 Ensure nosuid option set on /dev/shm partition OK">> ~/hardening.log
				echo "1.1.17 Ensure noexec option set on /dev/shm partition OK">> ~/hardening.log
			else
				sed -i '/shm /d' /etc/fstab
				echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
				echo "1.1.15 Ensure nodev option set on /dev/shm partition OK">> ~/hardening.log
				echo "1.1.16 Ensure nosuid option set on /dev/shm partition OK">> ~/hardening.log
				echo "1.1.17 Ensure noexec option set on /dev/shm partition OK">> ~/hardening.log
			fi
	else
				echo "1.1.15 Ensure nodev option set on /dev/shm partition OK">> ~/hardening.log
				echo "1.1.16 Ensure nosuid option set on /dev/shm partition OK">> ~/hardening.log
				echo "1.1.17 Ensure noexec option set on /dev/shm partition OK">> ~/hardening.log
	fi	


echo "1.1.18 Ensure nodev option set on removable media partitions NO APLICA">> ~/hardening.log
echo "1.1.19 Ensure nosuid option set on removable media partitions NO APLICA">> ~/hardening.log
echo "1.1.20 Ensure noexec option set on removable media partitions NO APLICA">> ~/hardening.log


### Set Sticky bit in all-writable directories ####

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
	if [ $? -eq 0 ]
		then
			echo "1.1.21 Ensure sticky bit is set on all world-writable directories OK">> ~/hardening.log
		else
			df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
			echo "1.1.21 Ensure sticky bit is set on all world-writable directories OK">> ~/hardening.log
	fi


### Disable Automounting ###
systemctl list-unit-files | grep autofs| grep enable
	if [ $? -eq 0 ]
		then
			systemctl disable autofs; echo "1.1.22 Disable Automounting OK">> ~/hardening.log
		else
			echo "1.1.22 Disable Automounting OK">> ~/hardening.log
	fi


### Ensure gpgcheck is globally activated ###
grep ^gpgcheck /etc/yum.conf
	if [ $? -eq 0 ]
		then
			sed -i 's/gpgcheck=0/gpgcheck=1/g' /etc/yum.conf
			echo "1.2.3 Ensure gpgcheck is globally activated OK">> ~/hardening.log
		else
			echo "1.2.3 Ensure gpgcheck is globally activated OK">> ~/hardening.log
	fi
	
	

### Installing AIDE for integrity checking ###
rpm -q aide
	if [ $? -eq 0 ]
		then
			echo "1.3.1 Ensure AIDE is installed OK">> ~/hardening.log
		else
			yum install -y aide
				if [ $? -eq 0 ]
				then
					aide --init
					mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
					echo "1.3.1 Ensure AIDE is installed OK">> ~/hardening.log
				else
					echo "AIDE no pudo ser instalado, favor revisar tus REPOSITORIOS y continuar...">> ~/hardening.log
				fi
	fi

	
### Crontab for filesystem integrity check ###
crontab -u root -l | grep aide
	if [ $? -eq 0 ]
		then
			echo "1.3.2 Ensure filesystem integrity is regularly checked OK" >> ~/hardening.log
		else
			echo "0 5 * * * /usr/sbin/aide --check" >> /var/spool/cron/root
			echo "1.3.2 Ensure filesystem integrity is regularly checked OK" >> ~/hardening.log
	fi



### Ensure permissions on bootloader config are configured ###
chown root:root /boot/grub2/grub.cfg 
chmod og-rwx /boot/grub2/grub.cfg
echo "1.4.1 Ensure permissions on bootloader config are configured OK">> ~/hardening.log


echo "1.4.2 Ensure bootloader password is set NO APLICA">> ~/hardening.log
echo "1.4.3 Ensure authentication required for single user mode NO APLICA">> ~/hardening.log
echo "1.5.4 Ensure prelink is disabled NO APLICA">> ~/hardening.log

echo "1.5 Additional Process Hardening NO APLICA">> ~/hardening.log
echo "1.6 Mandatory Access Control NO APLICA">> ~/hardening.log
echo "1.7 Warning Banners NO APLICA">> ~/hardening.log


### Ensure updates, patches, and additional security software are installed ###
yum update --security -y
	if [ $? -eq 0 ]
		then
		echo "1.8 Ensure updates, patches, and additional security software are installed OK">> ~/hardening.log
	else
		echo "1.8 Ensure updates, patches, and additional security software are installed OK">> ~/hardening.log
	fi


### NTP SERVICE ###

### restrict ipv4 enable option - NESSUS FIX REQUIREMENT ###
grep '^restrict default' /etc/ntp.conf 2>/dev/null
	if [ $? -eq 0 ]
		then
			echo "Parametro restrict ipv4 ya se encuentra habilitado, continuar..."
		else
			sed -i 's/#restrict default/restrict default/g' /etc/ntp.conf 2>/dev/null
			echo "parametro NTP restrict habilitado"
	fi

### restrict ipv6 enable option - NESSUS FIX REQUIREMENT ###
grep '^restrict -6 default' /etc/ntp.conf 2>/dev/null
	if [ $? -eq 0 ]
		then
			echo "Parametro restrict ipv6 ya se encuentra habilitado, continuar..."
		else
			sed -i 's/#restrict -6 default/restrict -6 default/g' /etc/ntp.conf 2>/dev/null
			echo "parametro NTP restrict habilitado"
	fi


### Disable monitor on NTP Service - NESSUS FIX REQUIREMENT ###
grep '^disable monitor' /etc/ntp.conf 2>/dev/null
	if [ $? -eq 0 ]
		then
			echo "Parametro monitor habilitado, continuar..." 
		else
			echo "disable monitor" >> /etc/ntp.conf
			echo "parametro NTP monitor deshabilitado"
	fi

systemctl restart ntpd && systemctl enable ntpd
echo "2.2.1.2 Ensure ntp is configured OK" >>~/hardening.log


# #### enable chrony ### NO APLICA
# systemctl list-unit-files | grep chronyd| grep enabled
	# if [ $? -eq 0 ]
		# then 
			# echo "2.2.1.3 Ensure chrony is configured OK" >>~/hardening.log
		# else
			# echo "server  172.30.1.42 prefer iburst 
# driftfile /var/lib/chrony/drift 
# makestep 1.0 3 
# rtcsync 
# keyfile /etc/chrony.keys 
# logdir /var/log/chrony 
# log measurements statistics tracking" > /etc/chrony.conf
			# systemctl chronyd restart && systemctl chronyd enable
			# echo "2.2.1.3 Ensure chrony is configured OK">>~/hardening.log
	# fi
	

systemctl stop chronyd && systemctl disable chronyd
echo "2.2.1.3 Ensure chrony is configured NO APLICA" >>~/hardening.log
	

echo "2.2.2 Ensure X Window System is not installed NO APLICA" >>~/hardening.log



## disabling packet redirection ###
sysctl -w net.ipv4.conf.all.send_redirects=0 
sysctl -w net.ipv4.conf.default.send_redirects=0 
sysctl -w net.ipv4.route.flush=1
echo "3.1.2 Ensure packet redirect sending is disabled OK" >>~/hardening.log


### ensure source routed packets are not accepted ##
sysctl -w net.ipv4.conf.all.accept_source_route=0 
sysctl -w net.ipv4.conf.default.accept_source_route=0 
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.tcp_syncookies=1
echo "3.2.1 Ensure source routed packets are not accepted OK" >>~/hardening.log


### Ensure ICMP redirects are not accepted ###
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
echo "3.2.2 Ensure ICMP redirects are not accepted OK" >>~/hardening.log

### Ensure suspicious packets are logged ###
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
echo "3.2.4 Ensure suspicious packets are logged OK" >>~/hardening.log

### Ensure broadcast ICMP requests are ignored ###
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
echo "3.2.5 Ensure broadcast ICMP requests are ignored OK" >>~/hardening.log

### Ensure bogus ICMP responses are ignored ###
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
echo "3.2.6 Ensure bogus ICMP responses are ignored OK" >>~/hardening.log

### Ensure Reverse Path Filtering is enabled ###
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
echo "3.2.7 Ensure Reverse Path Filtering is enabled OK" >>~/hardening.log

### Ensure TCP SYN Cookies is enabled ###
sysctl -w net.ipv4.tcp_syncookies=1
echo "3.2.8 Ensure TCP SYN Cookies is enabled OK" >>~/hardening.log


echo "3.3.1 Ensure IPv6 router advertisements are not accepted NO APLICA" >>~/hardening.log
echo "3.3.2 Ensure IPv6 redirects are not accepted NO APLICA" >>~/hardening.log
echo "3.3.3 Ensure IPv6 is disabled NO APLICA" >>~/hardening.log

echo "3.4 TCP Wrappers NO APLICA" >>~/hardening.log
echo "3.5 Uncommon Network Protocols NO APLICA" >>~/hardening.log
echo "3.6 Firewall Configuration NO APLICA" >>~/hardening.log


### Ensure system is disabled when audit logs are full ###
grep '^space_left_action = email' /etc/audit/auditd.conf
	if [ $? -eq 0 ]
	then
		echo "El parametro ya existe en auditd.conf, continuar..."
	else
		sed -i '/^space_left_action/d' /etc/audit/auditd.conf
		echo  "space_left_action = email">>/etc/audit/auditd.conf
		echo "El parametro space_left_action ha sido agregado en auditd.conf, continuar..."
	fi

grep '^action_mail_acct = root' /etc/audit/auditd.conf
	if [ $? -eq 0 ]
	then
		echo "El parametro ya existe en auditd.conf, continuar..."
	else
		sed -i '/^action_mail_acct /d' /etc/audit/auditd.conf 
		echo  "action_mail_acct = root">>/etc/audit/auditd.conf
		echo "El parametro action_mail_acct ha sido agregado en auditd.conf, continuar..."
	fi

grep '^admin_space_left_action = halt' /etc/audit/auditd.conf
	if [ $? -eq 0 ]
	then
		echo "El parametro ya existe en auditd.conf, continuar..." 
	else
		sed -i '/^admin_space_left_action /d' /etc/audit/auditd.conf 
		echo  "admin_space_left_action = halt">>/etc/audit/auditd.conf
		echo "El parametro admin_space_left_action ha sido agregado en auditd.conf, continuar..." 
	fi
echo "4.1.1.2 Ensure system is disabled when audit logs are full OK" >> ~/hardening.log


### Ensure audit logs are not automatically deleted ###
grep '^max_log_file_action = keep_logs' /etc/audit/auditd.conf
	if [ $? -eq 0 ]
	then
		echo "El parametro ya existe en auditd.conf, continuar..." 
	else
		sed -i '/^max_log_file_action /d' /etc/audit/auditd.conf 
		echo  "max_log_file_action = keep_logs">>/etc/audit/auditd.conf
		echo "El parametro max_log_file_action ha sido agregado en auditd.conf, continuar..." 
	fi
echo "4.1.1.3 Ensure audit logs are not automatically deleted OK" >> ~/hardening.log



## Ensure auditd service is enabled ##
systemctl list-unit-files | grep auditd | grep enabled
	if [ $? -eq 0 ]
		then
			systemctl disable auditd; 
		#	echo "El servicio auditd ha sido desactivado, continuar..." >>~/hardening.log
		else
			echo "El servicio auditd no se encuentra activo o instalado, continuar..."
	fi
echo "4.1.2 Ensure auditd service is enabled OK" >> ~/hardening.log


### Ensure auditing for processes that start prior to auditd is enabled ###

grep "^\s*linux" /boot/grub2/grub.cfg | grep audit=1
	if [ $? -eq 0 ]
	then
		echo "linea agregada en grub2 file, continuar..."
	else
		echo GRUB_CMDLINE_LINUX="audit=1" >> /etc/default/grub
		grub2-mkconfig -o /boot/grub2/grub.cfg
	fi
echo "4.1.3 Ensure auditd service is enabled OK" >> ~/hardening.log


## Ensure events that modify date and time information are collected ###
grep time-change /etc/audit/audit.rules
	if [ $? -eq 0 ]
	then
		echo "4.1.4 Ensure events that modify date and time information are collected OK" >>~/hardening.log
	else
		echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
		echo "4.1.4 Ensure events that modify date and time information are collected OK" >>~/hardening.log
	fi

## Ensure events that modify user/group information are collected ##
grep identity /etc/audit/audit.rules
	if [ $? -eq 0 ]
		then
		echo "4.1.5 Ensure events that modify user/group information are collected OK" >> ~/hardening.log
	else
		echo "-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules
		echo "4.1.5 Ensure events that modify user/group information are collected OK" >> ~/hardening.log
	fi


### change parameters on auditd.conf ###

sed -i 's/max_log_file_action = ROTATE/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf


## Ensure events that modify the system network environment are collected ##
grep system-locale /etc/audit/audit.rules
	if [ $? -eq 0 ]
	then
		echo "4.1.6 Ensure events that modify the system's network environment are collected OK" >> ~/hardening.log
	else
		echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale" >> /etc/audit/audit.rules
		echo "4.1.6 Ensure events that modify the system's network environment are collected OK" >> ~/hardening.log
	fi

## Ensure events that modify the system's Mandatory Access Controls are collected ##
grep MAC-policy /etc/audit/audit.rules
	if [ $? -eq 0 ]
	then
		echo "4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected OK" >> ~/hardening.log
	else
		echo "-w /etc/selinux/ -p wa -k MAC-policy 
-w /usr/share/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
		echo "4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected OK" >> ~/hardening.log
	fi

### Ensure login and logout events are collected ###
grep logins /etc/audit/audit.rules 
	if [ $? -eq 0 ]
	then
			echo "4.1.8 Ensure login and logout events are collected OK" >> ~/hardening.log
	else
			echo "-w /var/log/lastlog -p wa -k logins 
-w /var/run/faillock/ -p wa -k logins" >> /etc/audit/audit.rules
			echo "4.1.8 Ensure login and logout events are collected OK" >> ~/hardening.log
	fi


### Ensure session initiation information is collected ###
auditctl -l | grep session
	if [ $? -eq 0 ]
	then
		echo "4.1.9 Ensure session initiation information is collected OK" >> ~/hardening.log
	else
		echo "-w /var/run/utmp -p wa -k session 
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins" >> /etc/audit/audit.rules
		echo "4.1.9 Ensure session initiation information is collected OK" >> ~/hardening.log
	fi


### Ensure discretionary access control permission modification events are collected ###
auditctl -l | grep perm_mod
	if [ $? -eq 0 ]
	then
		echo "4.1.10 Ensure discretionary access control permission modification events are collected OK" >> ~/hardening.log
	else
		echo "-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod" >> /etc/audit/audit.rules
		echo "4.1.10 Ensure discretionary access control permission modification events are collected OK" >> ~/hardening.log
	fi


### Ensure unsuccessful unauthorized file access attempts are collected ###
grep access /etc/audit/audit.rules
	if [ $? -eq 0 ]
	then
		echo "4.1.11 Ensure unsuccessful unauthorized file access attempts are collected OK" >> ~/hardening.log
	else
		echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access" >> /etc/audit/audit.rules
		echo "4.1.11 Ensure unsuccessful unauthorized file access attempts are collected OK" >> ~/hardening.log
	fi

### Ensure use of privileged commands is collected ###
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >/dev/null
	if [ $? -eq 0 ]
	then
		echo "4.1.12 Ensure use of privileged commands is collected OK" >> ~/hardening.log
	else
		echo "4.1.12 Ensure use of privileged commands is collected NO APLICA" >> ~/hardening.log
	fi


## Ensure successful file system mounts are collected ##
grep mounts /etc/audit/audit.rules
	if [ $? -eq 0 ]
	then
		echo "4.1.13 Ensure successful file system mounts are collected OK" >> ~/hardening.log
	else
		echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts 
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
		echo "4.1.13 Ensure successful file system mounts are collected OK" >> ~/hardening.log
	fi

## Ensure file deletion events by users are collected ##
grep delete /etc/audit/audit.rules
	if [ $? -eq 0 ]
	then
		echo "4.1.14 Ensure file deletion events by users are collected OK" >> ~/hardening.log
	else
		echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
		echo "4.1.14 Ensure file deletion events by users are collected OK" >> ~/hardening.log
	fi
	
## Ensure changes to system administration scope (sudoers) is collected ##
grep scope /etc/audit/audit.rules
	if [ $? -eq 0 ]
	then
		echo "4.1.15 Ensure changes to system administration scope (sudoers) is collected OK" >> ~/hardening.log
	else
		echo "-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/audit.rules
		echo "4.1.15 Ensure changes to system administration scope (sudoers) is collected OK" >> ~/hardening.log
	fi
	
## Ensure system administrator actions (sudolog) are collected ##
grep actions /etc/audit/audit.rules
	if [ $? -eq 0 ]
	then
		echo "4.1.16 Ensure system administrator actions (sudolog) are collected OK" >> ~/hardening.log
	else
		echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules
		echo "4.1.16 Ensure system administrator actions (sudolog) are collected OK" >> ~/hardening.log
	fi


##  Ensure kernel module loading and unloading is collected ##
auditctl -l | grep modules
	if [ $? -eq 0 ]
	then
		echo "4.1.17 Ensure kernel module loading and unloading is collected OK" >> ~/hardening.log
	else
		echo "-a always,exit -F arch=b32 -S create_module,init_module,delete_module,finit_module -F key=modules
-a always,exit -F arch=b64 -S create_module,init_module,delete_module,finit_module -F key=modules
-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/rmmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules
		echo "4.1.17 Ensure kernel module loading and unloading is collected OK" >> ~/hardening.log
	fi


## 	Ensure the audit configuration is immutable ##
grep "^\s*[^#]" /etc/audit/audit.rules | tail -1 | grep "-e 2"
	if [ $? -eq 0 ]
	then
		echo "4.1.18 Ensure the audit configuration is immutable OK" >> ~/hardening.log
	else
		echo "-e 2" >> /etc/audit/audit.rules
		echo "4.1.18 Ensure the audit configuration is immutable OK">> ~/hardening.log
	fi


## Ensure rsyslog Service is enabled ##

systemctl list-unit-files | grep rsyslog | grep enabled
	if [ $? -eq 0 ]
		then
			echo "4.2.1.1 Ensure rsyslog Service is enabled OK">>~/hardening.log
		else
			systemctl enable rsyslog
			echo "4.2.1.1 Ensure rsyslog Service is enabled OK">>~/hardening.log
	fi


echo "4.2.1.2 Ensure logging is configured NO APLICA">> ~/hardening.log

	
## Ensure rsyslog default file permissions configured ##

grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf
	if [ $? -eq 0 ]
		then
			echo "4.2.1.3 Ensure rsyslog default file permissions configured OK" >> ~/hardening.log
		else
			echo '$FileCreateMode 0640' >> /etc/rsyslog.conf
			echo "4.2.1.3 Ensure rsyslog default file permissions configured OK" >> ~/hardening.log
	fi


### Ensure rsyslog is configured to send logs to a remote log host ###
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
	if [ $? -eq 0 ]
		then
			echo "4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host OK">> ~/hardening.log
		else
			echo "*.*  @10.168.15.17" >> /etc/rsyslog.conf
			echo "4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host OK">> ~/hardening.log
	fi


echo "4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts NO APLICA">> ~/hardening.log
echo "4.2.2.1 Ensure syslog-ng service is enabled NO APLICA">> ~/hardening.log
echo "4.2.2.2 Ensure logging is configured NO APLICA">> ~/hardening.log
echo "4.2.2.3 Ensure syslog-ng default file permissions configured NO APLICA">> ~/hardening.log
echo "4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host NO APLICA">> ~/hardening.log
echo "4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts NO APLICA">> ~/hardening.log

### Ensure rsyslog or syslog-ng is installed ###
rpm -q rsyslog
	if [ $? -eq 0 ]
	then
		echo "4.2.3 Ensure rsyslog or syslog-ng is installed OK">> ~/hardening.log
	else
		echo "4.2.3 Ensure rsyslog or syslog-ng is installed NO APLICA">> ~/hardening.log
	fi


echo "4.2.4 Ensure permissions on all logfiles are configured NO APLICA">> ~/hardening.log
echo "4.3 Ensure logrotate is configured NO APLICA">> ~/hardening.log
echo "5.1 Configure cron NO APLICA">> ~/hardening.log


## Ensure permissions on /etc/ssh/sshd_config are configured ##

ls -l /etc/ssh/sshd_config | tr -s " " " "|cut -f3 -d" "|grep root && ls -l /etc/ssh/sshd_config | tr -s " " " "|cut -f4 -d" "|grep root
	if [ $? -eq 0 ]
		then
			echo "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured OK" >> ~/hardening.log
		else
			chown root:root /etc/ssh/sshd_config
			echo "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured OK">> ~/hardening.log
	fi


##  Ensure SSH Protocol is set to 2 ##

grep "^Protocol" /etc/ssh/sshd_config
	if [ $? -eq 0 ]
		then
			echo "5.2.2 Ensure SSH Protocol is set to 2 OK" >> ~/hardening.log
		else
			echo "Protocol 2" >> /etc/ssh/sshd_config
			echo "5.2.2 Ensure SSH Protocol is set to 2 OK" >> ~/hardening.log
	fi


## Ensure SSH LogLevel is set to INFO ##

grep "^LogLevel INFO" /etc/ssh/sshd_config
	if [ $? -eq 0 ]
		then
			echo "5.2.3 Ensure SSH LogLevel is set to INFO OK" >> ~/hardening.log
		else
			echo "LogLevel INFO" >> /etc/ssh/sshd_config
			echo "5.2.3 Ensure SSH LogLevel is set to INFO OK" >> ~/hardening.log
	fi

##  Ensure SSH X11 forwarding is disabled ##
grep '^X11Forwarding no' /etc/ssh/sshd_config
if [  $? -eq 0 ]
		then
			echo "5.2.4 Ensure SSH X11 forwarding is disabled OK" >> ~/hardening.log
		else
			sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config 
			echo "5.2.4 Ensure SSH X11 forwarding is disabled OK" >> ~/hardening.log
		fi

## Ensure SSH MaxAuthTries is set to 4 or less ##
grep '^MaxAuthTries' /etc/ssh/sshd_config
if [  $? -eq 0 ]
		then
			echo "5.2.5 Ensure SSH MaxAuthTries is set to 4 or less OK" >> ~/hardening.log
		else
			sed -i 's/#MaxAuthTries/MaxAuthTries/g' /etc/ssh/sshd_config
			echo "5.2.5 Ensure SSH MaxAuthTries is set to 4 or less OK" >> ~/hardening.log
		fi

## Ensure SSH IgnoreRhosts is enabled ##
grep "^IgnoreRhosts" /etc/ssh/sshd_config
if [  $? -eq 0 ]
		then
			echo "5.2.6 Ensure SSH IgnoreRhosts is enabled OK" >> ~/hardening.log
		else
			sed -i 's/#IgnoreRhosts/IgnoreRhosts/g' /etc/ssh/sshd_config
			echo "5.2.6 Ensure SSH IgnoreRhosts is enabled OK" >> ~/hardening.log
		fi


## Ensure SSH HostbasedAuthentication is disabled ##
grep "^HostbasedAuthentication" /etc/ssh/sshd_config
if [  $? -eq 0 ]
		then
			echo "5.2.7 Ensure SSH HostbasedAuthentication is disabled OK" >> ~/hardening.log
		else
			sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
			echo "5.2.7 Ensure SSH HostbasedAuthentication is disabled OK" >> ~/hardening.log
		fi


### NESSUS SCAN FIX REQUIREMENT ##
grep '^AllowTcpForwarding' /etc/ssh/sshd_config
if [  $? -eq 0 ]
		then
			echo "Parametros AllowTcpForwarding deshabilitado, continuar..." 
		else
			sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding no/g' /etc/ssh/sshd_config 
			echo "AllowTcpForwarding agregado, continuar..."
		fi


grep '^PermitRootLogin no' /etc/ssh/sshd_config
if [  $? -eq 0 ]
		then
			echo "5.2.8 Ensure SSH root login is disabled OK" >> ~/hardening.log
		else
			sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
			sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
			echo "5.2.8 Ensure SSH root login is disabled OK" >> ~/hardening.log
		fi


grep '^PermitEmptyPasswords' /etc/ssh/sshd_config
if [  $? -eq 0 ]
		then
			echo "5.2.9 Ensure SSH PermitEmptyPasswords is disabled OK" >> ~/hardening.log
		else
			sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
			echo "5.2.9 Ensure SSH PermitEmptyPasswords is disabled OK" >> ~/hardening.log
		fi


grep 'PermitUserEnvironment' /etc/ssh/sshd_config
if [  $? -eq 0 ]
		then
			echo "5.2.10 Ensure SSH PermitUserEnvironment is disabled OK" >> ~/hardening.log
		else
			sed -i 's/#PermitUserEnvironment/PermitUserEnvironment/g' /etc/ssh/sshd_config
			echo "5.2.10 Ensure SSH PermitUserEnvironment is disabled OK" >> ~/hardening.log
		fi


grep 'MACs' /etc/ssh/sshd_config
if [  $? -eq 0 ]
		then
			echo "5.2.11 Ensure only approved MAC algorithms are used OK" >> ~/hardening.log
		else
			echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config
			echo "5.2.11 Ensure only approved MAC algorithms are used OK" >> ~/hardening.log
		fi


grep "^ClientAliveCountMax" /etc/ssh/sshd_config
if [  $? -eq 0 ]
		then
			echo "5.2.12 Ensure SSH Idle Timeout Interval is configured OK" >> ~/hardening.log
		else
			sed -i 's/#ClientAliveCountMax/ClientAliveCountMax/g' /etc/ssh/sshd_config
			echo "5.2.12 Ensure SSH Idle Timeout Interval is configured OK" >> ~/hardening.log
		fi

grep "^LoginGraceTime" /etc/ssh/sshd_config
if [  $? -eq 0 ]
		then
			echo "5.2.13 Ensure SSH LoginGraceTime is set to one minute or less OK" >> ~/hardening.log
		else
			sed -i 's/#LoginGraceTime/LoginGraceTime/g' /etc/ssh/sshd_config
			echo "5.2.13 Ensure SSH LoginGraceTime is set to one minute or less OK" >> ~/hardening.log
		fi

echo "5.2.14 Ensure SSH access is limited NO APLICA" >> ~/hardening.log

grep "^Banner" /etc/ssh/sshd_config
if [  $? -eq 0 ]
		then
			echo "5.2.15 Ensure SSH warning banner is configured OK" >> ~/hardening.log
		else
			echo "
###################################### AVISO ########################################
# Procesadora de Medios de Pago.                                                    #
# NOTA: El acceso a este servidor, sin la previa autorizacion del encargado de      #
# tecnologia, puede ser considerado violacion y usted ser sometido a la justicia.   #
#####################################################################################
 " > /etc/issue.net
			echo "Banner /etc/issue.net " >> /etc/ssh/sshd_config
			echo "5.2.15 Ensure SSH warning banner is configured OK" >> ~/hardening.log
		fi

systemctl restart sshd && systemctl enable sshd


### Ensure password creation requirements are configured ###
grep "pam_pwquality.so" /etc/pam.d/password-auth
	if [ $? -eq 0 ]
	then
		echo "pam_pwquality parametro encontrado"
	else
		echo "password requisite pam_pwquality.so try_first_pass retry=3" >> /etc/pam.d/password-auth
	fi
grep "^minlen" /etc/security/pwquality.conf
	if [ $? -eq 0 ]
	then
		sed -i 's/minlen=/minlen=14/g' /etc/security/pwquality.conf
	fi
echo "5.3.1 Ensure password creation requirements are configured OK" >> ~/hardening.log


### Ensure lockout for failed password attempts is configured ###
egrep -ia 'auth|sufficient|default=die|deny=' /etc/pam.d/password-auth
	if [ $? -eq 0 ]
	then
		echo "5.3.2 Ensure lockout for failed password attempts is configured OK" >> ~/hardening.log
	else
		echo "5.3.2 Ensure lockout for failed password attempts is configured NO APLICA" >> ~/hardening.log
	fi

### Ensure password reuse is limited ###
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth
	if [ $? -eq 0 ]
	then
		echo "salida valida!"
	else
		echo "password sufficient pam_unix.so remember=5" >> /etc/pam.d/password-auth
	fi
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth
	if [ $? -eq 0 ]
	then
		echo "salida valida!"
	else
		echo "password sufficient pam_unix.so remember=5" >> /etc/pam.d/system-auth
	fi
echo "5.3.3 Ensure password reuse is limited OK" >> ~/hardening.log


### Ensure password hashing algorithm is SHA-512 ###
grep sha512 /etc/pam.d/password-auth /etc/pam.d/system-auth
	if [ $? -eq 0 ]
	then
		echo "5.3.4 Ensure password hashing algorithm is SHA-512 OK" >> ~/hardening.log
	else
		echo "5.3.4 Ensure password hashing algorithm is SHA-512 NO APLICA" >> ~/hardening.log
	fi


### Ensure Password expiration is set to 30 days ###

grep 'PASS_MAX_DAYS     30' /etc/login.defs
	if [ $? -eq 0 ]
		then
			echo "Password expiration date valido de 30 dias, continuar..."
		else
			sed -i 's/PASS_MAX_DAYS     90/PASS_MAX_DAYS     30/g' /etc/login.defs
			for passuser in $(egrep 'ksh|bash|/bin/sh|zsh' /etc/passwd | cut -f1 -d ":")
				do
					chage --maxdays 30 $passuser
				done
			echo "Password expiration date valido de 30 dias habilitado, continuar..."
	fi
echo "5.4.1.1 Ensure password expiration is 365 days or less OK" >> ~/hardening.log

	
### Ensure min day is set to 7 ###	

grep 'PASS_MIN_DAYS   7' /etc/login.defs
	if [ $? -eq 0 ]
		then
			echo "Password min days valido de 7 dias, continuar..."
		else
			sed -i 's/PASS_MIN_DAYS   0/PASS_MIN_DAYS   7/g' /etc/login.defs
			for passmin in $(egrep 'ksh|bash|/bin/sh|zsh' /etc/passwd | cut -f1 -d ":")
				do
					chage --mindays 0 $passmin
				done
			echo "Password min days valido de 7 dias habilitado, continuar..."
	fi
echo "5.4.1.2 Ensure minimum days between password changes is 7 or more OK" >> ~/hardening.log


# ### Ensure warning day is 7 ### 
grep 'PASS_WARN_AGE   7' /etc/login.defs
	if [ $? -eq 0 ]
		then
			echo "Passwd warning days valido de 7 dias, continuar..."
		else	
			sed -i 's/PASS_WARN_AGE   7/PASS_WARN_AGE   7/g' /etc/login.defs
			for warnpass in $(egrep 'ksh|bash|/bin/sh|zsh' /etc/passwd | cut -f1 -d ":")
				do
					chage --warndays 7 $warnpass
				done
			echo "Passwd warning days valido de 7 dias habilitado, continuar..."
	fi
echo "5.4.1.3 Ensure password expiration warning days is 7 or more OK" >> ~/hardening.log


echo "5.4.1.4 Ensure inactive password lock is 30 days or less NO APLICA" >> ~/hardening.log
echo "5.4.1.5 Ensure all users last password change date is in the past NO APLICA" >> ~/hardening.log

nologin=$(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print}')
	if [ $? -eq 0 ]
	then
		echo "5.4.2 Ensure system accounts are non-login OK" >> ~/hardening.log
	else
		for file in $nologin
			do
				usermod -s /sbin/nologin $file
			done
			echo "5.4.2 Ensure system accounts are non-login OK" >> ~/hardening.log	
	fi

grep "^root:" /etc/passwd | cut -f4 -d:
	if [ $? -eq 0 ]
	then
			echo "5.4.3 Ensure default group for the root account is GID 0 OK" >> ~/hardening.log
	else
			usermod -g 0 root
			echo "5.4.3 Ensure default group for the root account is GID 0 OK" >> ~/hardening.log	
	fi


echo "5.4.4 Ensure default user umask is 027 or more restrictive NO APLICA" >> ~/hardening.log

### Ensure default user shell timeout is 900 seconds or less ###
grep "^TMOUT" /etc/bashrc /etc/profile
	if [ $? -eq 0 ]
	then
		echo "5.4.5 Ensure default user shell timeout is 900 seconds or less OK" >> ~/hardening.log
	else
		echo "TMOUT=600" >> /etc/bashrc
		echo "TMOUT=600" >> /etc/profile
		echo "5.4.5 Ensure default user shell timeout is 900 seconds or less OK" >> ~/hardening.log
	fi

echo "5.5 Ensure root login is restricted to system console NO APLICA" >> ~/hardening.log
echo "5.6 Ensure access to the su command is restricted NO APLICA" >> ~/hardening.log


echo "6.1.1 Audit system file permissions NO APLICA" >> ~/hardening.log


## Ensure permissions on /etc/passwd are configured ##

stat -c %u /etc/passwd | grep 0 && stat -c %a /etc/passwd | grep 644
	if [ $? -eq 0 ]
		then
			echo "6.1.2 Ensure permissions on /etc/passwd are configured OK" >> ~/hardening.log
		else
			chown root:root /etc/passwd
			chmod 644 /etc/passwd
			echo "6.1.2 Ensure permissions on /etc/passwd are configured OK" >>~/hardening.log
	fi
	

## Ensure permissions on /etc/shadow are configured ##

stat -c %u /etc/shadow | grep 0 && stat -c %a /etc/shadow | grep 000
	if [ $? -eq 0 ]
		then
			echo "6.1.3 Ensure permissions on /etc/shadow are configured OK" >> ~/hardening.log
		else
			chown root:root /etc/shadow
			chmod 000 /etc/shadow
			echo "6.1.3 Ensure permissions on /etc/shadow are configured OK" >>~/hardening.log
	fi

## Ensure permissions on /etc/group are configured ##

stat -c %u /etc/group | grep 0 && stat -c %a /etc/group | grep 644
	if [ $? -eq 0 ]
		then
			echo "6.1.4 Ensure permissions on /etc/group are configured OK" >> ~/hardening.log
		else
			chown root:root /etc/group
			chmod 644 /etc/group
			echo "6.1.4 Ensure permissions on /etc/group are configured OK" >>~/hardening.log
	fi

## Ensure permissions on /etc/gshadow are configured ##

stat -c %u /etc/gshadow | grep 0 && stat -c %a /etc/gshadow | grep 000
	if [ $? -eq 0 ]
		then
			echo "6.1.5 Ensure permissions on /etc/gshadow are configured OK" >> ~/hardening.log
		else
			chown root:root /etc/gshadow
			chmod 000 /etc/gshadow
			echo "6.1.5 Ensure permissions on /etc/gshadow are configured OK" >>~/hardening.log
	fi

stat -c %u /etc/passwd- | grep 0 && stat -c %a /etc/passwd- | grep 644
	if [ $? -eq 0 ]
		then
			echo "6.1.6 Ensure permissions on /etc/passwd- are configured OK" >> ~/hardening.log
		else
			chown root:root /etc/passwd-
			chmod u-x,go-wx /etc/passwd-
			echo "6.1.6 Ensure permissions on /etc/passwd- are configured OK" >>~/hardening.log
	fi

	
stat -c %u /etc/shadow- | grep 0 && stat -c %a /etc/shadow- | grep 000
	if [ $? -eq 0 ]
		then
			echo "6.1.7 Ensure permissions on /etc/shadow- are configured OK" >> ~/hardening.log
		else
			chown root:root /etc/shadow-
			chmod 000 /etc/shadow-
			echo "6.1.7 Ensure permissions on /etc/shadow- are configured OK" >>~/hardening.log
	fi


stat -c %u /etc/group- | grep 0 && stat -c %a /etc/group- | grep 644
	if [ $? -eq 0 ]
		then
			echo "6.1.8 Ensure permissions on /etc/group- are configured OK" >> ~/hardening.log
		else
			chown root:root /etc/group-
			chmod u-x,go-wx /etc/group-
			echo "6.1.8 Ensure permissions on /etc/group- are configured OK" >>~/hardening.log
	fi


stat -c %u /etc/gshadow- | grep 0 && stat -c %a /etc/gshadow- | grep 000
	if [ $? -eq 0 ]
		then
			echo "6.1.9 Ensure permissions on /etc/gshadow- are configured OK" >> ~/hardening.log
		else
			chown root:root /etc/gshadow-
			chmod 000 /etc/gshadow-
			echo "6.1.9 Ensure permissions on /etc/gshadow- are configured OK" >>~/hardening.log
	fi


### Ensure no world writable files exist ###
findCmd=$(find / -xdev -type f -perm -0002)
	if [ "$findCmd" == "" ]; then
			echo "6.1.10 Ensure no world writable files exist OK" >>~/hardening.log
		else
			#chmod 744 $findCmd
			echo "6.1.10 Ensure no world writable files exist (REVISAR)" >>~/hardening.log
	fi


### Ensure no unowned files or directories exist
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser
	if [ $? -eq 0 ]
		then
			echo "6.1.11 Ensure no unowned files or directories exist OK" >> ~/hardening.log
		else
			echo "6.1.11 Ensure no unowned files or directories exist OK" >>~/hardening.log
	fi


### Ensure no unowned files or directories exist
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup
	if [ $? -eq 0 ]
		then
			echo "6.1.12 Ensure no ungrouped files or directories exist OK" >> ~/hardening.log
		else
			echo "6.1.12 Ensure no ungrouped files or directories exist OK" >>~/hardening.log
	fi


## Ensure password fields are not empty ##
nopwd=$(cat /etc/shadow | awk -F: '($2 == "" ) { print $1}')
	if [ "$nopwd" == "" ]
		then
			echo "6.2.1 Ensure password fields are not empty OK" >> ~/hardening.log
		else
			passwd -l $nopwd
			echo "6.2.1 Ensure password fields are not empty OK" >> ~/hardening.log
		fi


## Ensure no legacy "+" entries exist in /etc/passwd ##
grep '^\+:' /etc/passwd
	if [ $? -eq 0 ]
		then
			echo "6.2.2 Ensure no legacy "+" entries exist in /etc/passwd OK" >> ~/hardening.log
		else
			sed -i '/^\+:/d' /etc/passwd
			echo "6.2.2 Ensure no legacy "+" entries exist in /etc/passwd OK" >> ~/hardening.log
		fi


## Ensure no legacy "+" entries exist in /etc/shadow ##
grep '^\+:' /etc/shadow
	if [ $? -eq 0 ]
		then
			echo "6.2.3 Ensure no legacy "+" entries exist in /etc/shadow OK" >> ~/hardening.log
		else
			sed -i '/^\+:/d' /etc/shadow
			echo "6.2.3 Ensure no legacy "+" entries exist in /etc/shadow OK" >> ~/hardening.log
		fi


## Ensure no legacy "+" entries exist in /etc/group ##
grep '^\+:' /etc/group
	if [ $? -eq 0 ]
		then
			echo "6.2.4 Ensure no legacy "+" entries exist in /etc/group OK" >> ~/hardening.log
		else
			sed -i '/^\+:/d' /etc/group
			echo "6.2.4 Ensure no legacy "+" entries exist in /etc/group OK" >> ~/hardening.log
		fi


## Ensure root is the only UID 0 account ##
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'
	if [ $? -eq 0 ]
		then
			echo "6.2.5 Ensure root is the only UID 0 account OK" >> ~/hardening.log
		else
			echo "6.2.5 Ensure root is the only UID 0 account NO APLICA" >> ~/hardening.log
		fi


### Ensure root PATH Integrity ###


echo "6.2.6 Ensure root PATH Integrity OK" >> ~/hardening.log


## Ensure all users' home directories exist ##
cmd4=$(cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)'  | egrep -v '/dev/null' | cut -d ":" -f6 | while read dirs; do if [ ! -d "$dirs" ]; then echo "$dirs";fi; done)
	if [ "$cmd4" == "" ]
		then
			echo "6.2.7 Ensure all users' home directories exist OK" >> ~/hardening.log
		else
			cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | grep -v '/dev/null'| cut -d ":" -f6 | while read dirs; do if [ ! -d "$dirs" ]; then mkdir -p "$dirs";fi; done
			echo "6.2.7 Ensure all users' home directories exist OK" >> ~/hardening.log
		fi


## Ensure users' home directories permissions are 750 or more restrictive ##
cmd5=$(cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | grep 'home' | cut -d ":" -f6 | while read dirs; do out=$(stat -c %a $dirs | cut -c1);if [ $out != "7" ];then echo "$out";fi; done)	
if [ "$cmd5" == "" ]
		then
			echo "6.2.8 Ensure users' home directories permissions are 750 or more restrictive OK" >> ~/hardening.log
		else
			echo "6.2.8 Ensure users' home directories permissions are 750 or more restrictive NO APLICA" >> ~/hardening.log
		fi
	

## Ensure users own their home directories ##
cmd6=$(cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | grep 'home' | cut -d ":" -f6 | while read dirs; do stat -L -c "%U" "$dirs"; done)
owner6=$(cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | grep 'home' | cut -d ":" -f1 | while read usrv; do echo "$usrv" ; done)
if [ "$cmd6" == "$owner6" ]
		then
			echo "6.2.9 Ensure users own their home directories OK" >> ~/hardening.log
		else
			echo "6.2.9 Ensure users own their home directories NO APLICA" >> ~/hardening.log
		fi

echo "6.2.10 Ensure users' dot files are not group or world writable NO APLICA" >> ~/hardening.log

## Ensure no users have .forward files ##
file1=$(cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | egrep 'root|home' | cut -d ":" -f6 | while read dirs; do ls "$dirs/.forward" 2>/dev/null; done)
if [ "$file1" == "" ]
		then
			echo "6.2.11 Ensure no users have .forward filess OK" >> ~/hardening.log
		else
			rm -f $file1
			echo "6.2.11 Ensure no users have .forward files OK" >> ~/hardening.log
		fi


## Ensure no users have .netrc files ##
file2=$(cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | egrep 'root|home' | cut -d ":" -f6 | while read dirs; do ls "$dirs/.netrc" 2>/dev/null; done)
if [ "$file2" == "" ]
		then
			echo "6.2.12 Ensure no users have .netrc files OK" >> ~/hardening.log
		else
			rm -f $file2
			echo "6.2.12 Ensure no users have .netrc files OK" >> ~/hardening.log
		fi


echo "6.2.13 Ensure users' .netrc Files are not group or world accessible NO APLICA" >> ~/hardening.log


## Ensure no users have .rhosts files ##
file3=$(cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | egrep 'root|home' | cut -d ":" -f6 | while read dirs; do ls "$dirs/.rhosts" 2>/dev/null; done)
if [ "$file3" == "" ]
		then
			echo "6.2.14 Ensure no users have .rhosts files OK" >> ~/hardening.log
		else
			rm -f $file3
			echo "6.2.14 Ensure no users have .rhosts files OK" >> ~/hardening.log
		fi


## Ensure all groups in /etc/passwd exist in /etc/group ##
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do 
grep -q -P "^.*?:[^:]*:$i:" /etc/group 
	if [ $? -ne 0 ] 
	then 
		echo "revisar grupo $i en /etc/group"
	fi
done
echo "6.2.15 Ensure all groups in /etc/passwd exist in /etc/group OK" >> ~/hardening.log


## Ensure no duplicate UIDs exist ##
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do 
[ -z "${x}" ] && break 
set - $x 
	if [ $1 -gt 1 ]
	then 
		users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs` 
		echo "Existen UID duplicados ($2): ${users}, revisar" 
	fi
done
echo "6.2.16 Ensure no duplicate UIDs exist OK" >> ~/hardening.log


## 6.2.17 Ensure no duplicate GIDs exist ##
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do 
[ -z "${x}" ] && break 
set - $x 
	if [ $1 -gt 1 ]
	then 
		groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs` 
		echo "Existen GID duplicados ($2): ${groups}, revisar" 
	fi
done
echo "6.2.17 Ensure no duplicate GIDs exist OK" >> ~/hardening.log


## Ensure no duplicate user names exist ## 
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do 
[ -z "${x}" ] && break 
set - $x 
	if [ $1 -gt 1 ]; 
	then 
		uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs` 
		echo "Existen usuarios duplicados ($2): ${uids}, revisar..." 
	fi 
done
echo "6.2.18 Ensure no duplicate user names exist OK" >> ~/hardening.log


## 6.2.19 Ensure no duplicate group names exist ##
cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do 
[ -z "${x}" ] && break 
set - $x 
	if [ $1 -gt 1 ]; 
	then 
		gids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs` 
		echo "Existen grupos duplicados ($2): ${gids}, revisar..." 
	fi 
done
echo "6.2.19 Ensure no duplicate group names exist OK" >> ~/hardening.log


### NESSUS SCAN FIX REQUIREMENT ###
grep '^com2sec' /etc/snmp/snmpd.conf 2>/dev/null
if [  $? -eq 0 ]
		then
			sed -i 's/com2sec/#com2sec/g' /etc/snmp/snmpd.conf
			systemctl restart snmpd
		#	echo "SNMP comunidad public deshabilitada, continuar..." >> ~/hardening.log
		else
			echo "No existe comunidad public habilitada, continuar..."
		fi


echo "Ejecucion finalizada, revisar el archivo hardening.log - `date` "; sleep 2
echo "Ejecucion finalizada, revisar el archivo hardening.log - `date` " >> ~/hardening.log

## END HERE ###
