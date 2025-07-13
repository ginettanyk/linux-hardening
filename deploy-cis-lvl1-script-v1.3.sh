#!/bin/bash

# ---------------------------------------------------------
# Name        - deploy-cis-lvl1-script.sh
# Version     - 1.3
# Shell       - Bourne Again Shell
# Purpose     - Performs CIS Hardening to 70%+
#		Level 1 is LDAP Friendly hardening
#		Level 2 is suited for DMZ/Public Facing
#               See handbook for manual tasks after
# Last Update - Sun 13/Jul /2025
# Programmer  - ginettanyk
# Usage       - as root within deploy dir 
#               ./deploy-cis-lvl1-script-v1.3.sh              
# ---------------------------------------------------------

####################################
##   remove / install packages    ##
####################################

export DEBIAN_FRONTEND=noninteractive
apt update
apt autoremove -y
apt purge -y nftables
apt purge -y ufw
apt install apparmor apparmor-utils apparmor-profiles auditd audispd-plugins libpam-pwquality iptables-persistent -y
#apt install aide ## perform this manually and initiate 

########################
## password hardening ##
########################

# pwquality filename variables
pwqpath=/etc/security
pwqconfig=$pwqpath/pwquality.conf

# check if pwquality.conf exists
if [ -f "$pwqconfig" ]
        then mv $pwqconfig $pwqconfig.ncc.$today
fi

cp pwquality.conf.deploy $pwqconfig


##################################
## install our auditd.conf file ##
##################################

# audit filename variables
auditpath=/etc/audit
auditconfig=$auditpath/auditd.conf

# check if auditd.conf exists
if [ -f "$auditconfig" ]
        then mv $auditconfig $auditconfig.ncc.$today
fi

cp auditd.conf.deploy $auditconfig

######################
## enforce apparmor ##
######################

aa-enforce /etc/apparmor.d/*
# alternatively set to complain
#aa-complain /etc/apparmor.d/*

#################################################
## /etc/default/grub ensure apparmor is loaded ##
#################################################

testapparmor=`cat /etc/default/grub | grep "apparmor=1" | wc -l`

if [ "$testapparmor" = 0 ]
        then
		echo "# CIS Hardening" | tee -a /etc/default/grub > /dev/null
		echo GRUB_CMDLINE_LINUX='"apparmor=1 security=apparmor"' | tee -a /etc/default/grub > /dev/null
fi

#################################################
##  /etc/default/grub ensure audit/log is set  ##
#################################################

testaudit=`cat /etc/default/grub | grep "audit=1" | wc -l`

if [ "$testaudit" = 0 ]
        then
                echo "# CIS Hardening" | tee -a /etc/default/grub > /dev/null
                echo GRUB_CMDLINE_LINUX='"audit=1"' | tee -a /etc/default/grub > /dev/null
fi

testbacklog=`cat /etc/default/grub | grep "audit_backlog_limit=8192" | wc -l`

if [ "$testbacklog" = 0 ]
        then
                echo "# CIS Hardening" | tee -a /etc/default/grub > /dev/null
                echo GRUB_CMDLINE_LINUX='"audit_backlog_limit=8192"' | tee -a /etc/default/grub > /dev/null
fi

testipv6=`cat /etc/default/grub | grep "ipv6.disable=1" | wc -l`

if [ "$testipv6" = 0 ]
        then
                echo "# CIS Hardening" | tee -a /etc/default/grub > /dev/null
                echo GRUB_CMDLINE_LINUX='"ipv6.disable=1"' | tee -a /etc/default/grub > /dev/null
fi

update-grub

##########################
## disable core dumping ##
##########################

echo "*  hard  core  0" >> /etc/security/limits.conf

sysctl -p

systemctl stop apport.service
systemctl disable apport.service

######################
## /etc/fstab tmpfs ##
######################

echo "# CIS Security for /tmp" >> /etc/fstab
echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
echo "tmpfs /dev/shm tmpfs nosuid,nodev,noexec 0 0" >> /etc/fstab

######################
## file permissions ##
######################

etc_motd=/etc/motd
if [ -f "$etc_motd" ]
        then 
		chown root:root $etc_motd
		chmod u-x $etc_motd
		chmod go-wx $etc_motd
	else
		touch $etc_motd
                chown root:root $etc_motd
                chmod u-x $etc_motd
		chmod go-wx $etc_motd
fi

chown root:root /etc/issue /etc/issue.net
chmod u-x /etc/issue /etc/issue.net
chmod go-wx /etc/issue /etc/issue.net

chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

chown root:root /etc/passwd- /etc/group-
chmod u-x /etc/passwd- /etc/group-
chmod go-rwx /etc/passwd- /etc/group-

chown root:root /etc/ssh/sshd_config
chmod go-rwx /etc/ssh/sshd_config

#######################################
## fixing cron files and permissions ##
#######################################

cron_deny=/etc/cron.deny
if [ -f "$cron_deny" ]
	then rm $cron_deny
fi

at_deny=/etc/at.deny
if [ -f "$at_deny" ]
	then rm $at_deny
fi

touch /etc/cron.allow 
touch /etc/at.allow 
chmod og-rwx /etc/cron.allow 
chmod og-rwx /etc/at.allow 
chown root:root /etc/cron.allow 
chown root:root /etc/at.allow
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
touch /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
chown root:root /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
chmod og-rwx /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
chown root:root /etc/cron.d
chmod 700 /etc/cron.d

################################
## configuration file updates ##
################################

# date stamp for file renaming
today="$(date +%y%m%d)"

# set paths adjust when dry runs are needed
modprobepath=/etc/modprobe.d
rootpath=/root

# filename variables
modprobecis=$modprobepath/CIS.conf

# check if CIS.conf exists
if [ -f "$modprobecis" ]
	then mv $modprobecis $modprobecis.ncc.$today
fi

cp CIS.conf.deploy $modprobecis

#####################
## network related ##
#####################

# Desktop not Server no wifi - this is done even without wireless adapter
#nmcli radio all off

######################
## sysctl ipv4 ipv6 ##
######################

cp etc_sysctl.d_cis.conf.deploy /etc/sysctl.d/99-cis.conf
sysctl -p

##########################
## ship logs to graylog ##
##########################

# filename variables
rpath=/etc
rsys=$rpath/rsyslog.conf

# check if rsyslog.conf exists
if [ -f "$rsys" ]
        then mv $rsys $rsys.ncc.$today
fi

cp rsyslog.conf.deploy $rsys

#################################
## replace issue and issue.net ##
#################################

cp issue.deploy /etc/issue
cp issue.net.deploy /etc/issue.net



#################
## audit rules ##
#################

audit_rules_path=/etc/audit/rules.d

rm $audit_rules_path/*
cp audit.rules.deploy/* $audit_rules_path/
cd $audit_rules_path/
for v in *.deploy ; do mv "$v"  "$(basename "$v" .deploy)"; done
cd -

######################
## journald config  ##
######################

# set config for journald
jpath=/etc/systemd
jconfig=$jpath/journald.conf

if [ -f "$jconfig" ]
        then mv $jconfig $jconfig.ncc.$today
fi

cp etc_systemd_journald.conf.deploy $jconfig

