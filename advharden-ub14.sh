#!/bin/bash

commence_hardening () {
    countdown
    tput reset
    compare_users
    question_user
    apt update
    enable_firewall
    disable_guest
    account_lockout
    audit_policy
    hacking_tools
    enable_AppArmor
    stig_complicance_measures
    unneeded_services
    sanity_for_defaults
    various_tweaks
}

countdown () {
    echo "Program will proceed with Ubuntu hardening in 3000 ms"
    for((i=3;i>0;i--));
    do
        echo "Starting in ${i}000 ms"
        sleep 1s
    done
    echo -e "Hardening operations commencing\n"
}

compare_users () {
    # Get array of allowed users from specified file
    allowedUsers=()
    n=1
    while read line
    do
        if [ ! -z "$line" ]
        then
            allowedUsers[$((${n}-1))]=$line
            echo "Allowed user $line found"
        fi
        n=$((n+1))
    done < $all_users_path
    echo -e "\nFound ${#allowedUsers[@]} total permitted users"

    allowedSudoUsers=()
    n=1
    while read line
    do
        if [ ! -z "$line" ]
        then
            allowedSudoUsers[$((${n}-1))]=$line
            echo "Allowed sudo user $line found"
        fi
        n=$((n+1))
    done < $sudo_users_path
    echo -e "\nFound ${#allowedSudoUsers[@]} permitted sudo users"

    echo -e "\nComparing lists to local system. Please stand by..."
    sysUsersArr=()
    n=1
    while read line
    do
        if [ ! -z "$line" ]
        then
            sysUsersArr[$((${n}-1))]=$line
        fi
        n=$((n+1))
    done < <(ls -ld /home/*/ | cut -f3 -d'/')
    echo -e "\nFound ${#sysUsersArr[@]} total system users"
    
    for system_user in "${sysUsersArr[@]}"
    do
        if [[ " ${allowedUsers[*]} " != *"$system_user"* ]]
        then
            read -p "Remove and purge disallowed user ${system_user} (y/n)? " answer
            if [ $answer == 'y' ] || [ $answer == 'Y' ]
            then
                userdel -r ${system_user}
            fi
        fi
    done
    
    # Verify users in sudo group
    sysAdminUsersArr=()
    n=1
    while read line
    do
        if [ ! -z "$line" ]
        then
            sysAdminUsersArr[$((${n}-1))]=$line
        fi
        n=$((n+1))
    done < <(grep '^sudo:.*$' /etc/group | cut -d: -f4 | tr , '\n')
    echo -e "\nFound ${#sysAdminUsersArr[@]} total sudo users"
    
    for system_admin_user in "${sysAdminUsersArr[@]}"
    do
        if [[ " ${allowedSudoUsers[*]} " != *"$system_admin_user"* ]]
        then
            read -p "Demote admin user ${system_admin_user} (y/n)? " answer
            if [ $answer == 'y' ] || [ $answer == 'Y' ]
            then
                gpasswd -d ${system_admin_user} sudo
            fi
        fi
    done

    # Ensure standard users are promoted if necessary
    for allowed_user in "${allowedSudoUsers[@]}"
    do
        if [[ " ${sysAdminUsersArr[*]} " != *"$allowed_user"* ]]
        then
            read -p "Promote standard user ${allowed_user} to admin (y/n)? " answer
            if [ $answer == 'y' ] || [ $answer == 'Y' ]
            then
                gpasswd -a ${allowed_user} sudo
            fi
        fi
    done
}

enable_firewall () {
    echo "Enabling ufw with default rule set"
    apt -y install ufw gufw
    service ufw start
    ufw default deny incoming
    ufw default allow outgoing
    ufw enable
}

disable_guest () {
    file_to_test="/etc/lightdm/lightdm.conf.d/50-no-guest.conf"
    if [ -f "$file_to_test" ]
    then
		echo "Guest account already disabled"
    else
    	echo "Disabling guest account"
        mkdir /etc/lightdm/lightdm.conf.d/
    	sh -c 'printf "[SeatDefaults]\nallow-guest=false\n" >/etc/lightdm/lightdm.conf.d/50-no-guest.conf'
    fi

}

account_lockout () {
	repeat_check_line=$(grep "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" /etc/pam.d/common-auth)
	if [ -z "$repeat_check_line" ]
	then
		echo "Configuring account lockout policy"
    	echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> /etc/pam.d/common-auth
	else
		echo "Account lockout policy is already properly configured. No changes were made"
	fi
    
}

audit_policy () {
    echo "Installing auditing program"
    apt -y install auditd
    echo "Enabling audits for the system"
    auditctl -e 1
}

hacking_tools () {
    echo "Attempting to remove hacking tools from blacklist"
    apt -y purge john
    apt -y purge nmap
    apt -y purge zenmap
    apt -y purge wireshark
    apt -y purge nikto
    apt -y purge sqlmap
    apt -y purge wapiti
    apt -y purge aircrack-ng
    apt -y purge reaver
    apt -y purge ettercap-*
    apt -y purge netcat
    apt -y purge driftnet
    apt -y purge kismet
    apt -y purge yersinia
    apt -y purge hydra
    apt -y purge ophcrack*
	
}

enable_AppArmor () {
	apt -y install libpam-apparmor
	service apparmor start
}

stig_complicance_measures () {
    echo "Initiating Ubuntu 16.04 STIG Semi-Compliance for Ubuntu 14.04"
	# Allow user initiation of session locks
    echo "installing vlock"
	apt install vlock
	# Limit number of concurrent sessions
	first_line="$(head -1 /etc/security/limits.conf)"
	if [ "$first_line" != "* hard maxlogins 10" ]
	then
		echo -e "\n\n\n"
		sed '1i * hard maxlogins 10' /etc/security/limits.conf
		read -p "In order to limit the number of concurrent sessions, is the draft file above acceptable (y/n)? " answer
		if [ $answer == 'y' ] || [ $answer == 'Y' ]
		then
			sed -i '1i * hard maxlogins 10' /etc/security/limits.conf
			echo "Changes written sucessfully"
		else
			echo "Manual review of the file /etc/security/limits.conf is needed. No changes were made"
		fi
	fi
	# Lock the root account to prevent direct logins
    echo "locking root account"
	passwd -l root
	# Account identifiers
    echo "account identifiers"
	useradd -D -f 35
	# Provide account access feedback
	line_text="session required pam_lastlog.so showfailed"
	search_line="$(grep "${line_text}" /etc/pam.d/login)"
	if [ -z "$search_line" ]
	then
		echo -e "\n\n\n"
		sed '1i session required pam_lastlog.so showfailed' /etc/pam.d/login
		read -p "In order to provide account access feedback, is the draft file above acceptable (y/n)? " answer
		if [ $answer == 'y' ] || [ $answer == 'Y' ]
		then
			sed -i '1i session required pam_lastlog.so showfailed' /etc/pam.d/login
			echo "Changes written sucessfully"
		else
			echo "Manual review of the file /etc/pam.d/login is needed. No changes were made"
		fi
	fi
    # Remove "*.shosts" files system-wide
    echo "The following .shosts files have been removed"
    find / -iname "*.shosts" -type f
    find / -iname "*.shosts" -type f -delete
	# Remove any "shosts.equiv" files system-wide
    echo "The following shosts.equiv files have been removed"
    find / -iname "shosts.equiv" -type f
    find / -iname "shosts.equiv" -type f -delete
    # Disable auto-mounting of USB Driver
    echo "Disabling auto-mount of USB Driver"
    echo "install usb-storage /bin/true" >> /etc/modprobe.d/DISASTIG.conf
    # Disable auto-mounting of file systems
    echo "Attempting to disable auto-mounting of file systems"
    service autofs stop
    # Disable x86 [CTRL + ALT + Del] Key Sequence
    echo "Disabling x86 [CTRL ALT DEL]"
    mv /etc/init/control-alt-delete.conf /etc/init/control-alt-delete.confDISABLED
    # Change group of /var/log to syslog
    echo "Changing group of /var/log to syslog"
    chgrp syslog /var/log 
    # Change owner of /var/log to root and ensure correct permissions
    echo "Changing owner of /var/log to root and ensuring correct permissions"
    chown root /var/log
    chmod 0770 /var/log
    # Change group of file /var/log/syslog to adm
    echo "Changing group of file /var/log/syslog to adm"
    chgrp adm /var/log/syslog
    # Change owner of /var/log/syslog to syslog and ensure correct permissions
    echo "Changing owner of /var/log/syslog to syslog and ensuring correct permissions"
    chown syslog /var/log/syslog
    chmod 0640 /var/log/syslog
    # Set permissions to prevent unnecessary selection of auditing events
    echo "Preventing unnecessary selection of audit events"
    chmod 0640 /etc/audit/auditd.conf
    chmod 0640 /etc/audit/audit.rules
    # Prevent overly-permissive file modes of SSH public/private host key files
    echo "Preventing overly-permissive file modes of SSH public/private host key files"
    chmod 0644 /etc/ssh/*key.pub
    chmod 0600 /etc/ssh/ssh_host*key
    service sshd restart
    # Enable TCP Syn-Cookies
    echo "Enabling TCP Syn-Cookies"
    sysctl -w net.ipv4.tcp_syncookies=1
    # Reject untrusted connections in postfix
    echo "Rejecting untrusted connections in postfix"
    postconf -e 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject'
    
}

unneeded_services () {
    echo "Changing potentially-exploitable services based on user choices"
    
    if [ $telnetYN == 'y' ] || [ $telnetYN == 'Y' ]
    then
        apt -y purge telnetd
        ufw deny 23
    elif [ $telnetYN == 'n' ] || [ $telnetYN == 'N' ]
    then
        ufw allow 23
        apt -y install telnetd
    fi

    if [ $nisYN == 'y' ] || [ $nisYN == 'Y' ]
    then
        apt -y purge nis
    elif [ $nisYN == 'n' ] || [ $nisYN == 'N' ]
    then
        apt -y install nis        
    fi

    if [ $rshYN == 'y' ] || [ $rshYN == 'Y' ]
    then
        apt -y purge rsh-server
        ufw deny 514
    elif [ $rshYN == 'n' ] || [ $rshYN == 'N' ]
    then
        ufw allow 514
        apt -y install rsh-server        
    fi

    if [ $vsftpdYN == 'y' ] || [ $vsftpdYN == 'Y' ]
    then
        apt -y purge vsftpd
        ufw deny ftp
    elif [ $vsftpdYN == 'n' ] || [ $vsftpdYN == 'N' ]
    then
        ufw allow ftp
        apt -y install vsftpd
    fi

    if [ $tftpYN == 'y' ] || [ $tftpYN == 'Y' ]
    then
        apt -y purge tftpd-hpa
        apt -y purge pure-ftpd
        ufw deny ftp
    elif [ $tftpYN == 'n' ] || [ $tftpYN == 'N' ]
    then
        ufw allow ftp
        apt -y install pure-ftpd
    fi

    if [ $sshYN == 'y' ] || [ $sshYN == 'Y' ]
    then
        apt -y purge ssh
        ufw deny ssh
    elif [ $sshYN == 'n' ] || [ $sshYN == 'N' ]
    then
        ufw allow ssh
        apt -y install ssh
    fi

    if [ $sambaYN == 'y' ] || [ $sambaYN == 'Y' ]
    then
        apt -y purge samba
        ufw deny 137/udp
        ufw deny 138/udp
        ufw deny 139/tcp
        ufw deny 445/tcp
    elif [ $sambaYN == 'n' ] || [ $sambaYN == 'N' ]
    then
        apt -y install samba
        ufw allow 137/udp
        ufw allow 138/udp
        ufw allow 139/tcp
        ufw allow 445/tcp
    fi

    if [ $mailYN == 'y' ] || [ $mailYN == 'Y' ]
    then    
        ufw deny 109    # pop2
        ufw deny 110    # pop3
        ufw deny 143    # imap
        ufw deny 25     # smtp
        ufw deny 465    # ssmtp
        ufw deny 585    # imap4-ssl
        ufw deny 993    # imaps
        ufw deny 995    # pop3s
        ufw deny 220    # imap v3
        ufw deny 587    # smtp (submission)
    elif [ $mailYN == 'n' ] || [ $mailYN == 'N' ]
    then
        ufw allow 109    # pop2
        ufw allow 110    # pop3
        ufw allow 143    # imap
        ufw allow 25     # smtp
        ufw allow 465    # ssmtp
        ufw allow 585    # imap4-ssl
        ufw allow 993    # imaps
        ufw allow 995    # pop3s
        ufw allow 220    # imap v3
        ufw allow 587    # smtp (submission)
    fi

    if [ $printYN == 'y' ] || [ $printYN == 'Y' ]
    then
        ufw deny cups
        ufw deny ipp
        ufw deny printer
    elif [ $printYN == 'n' ] || [ $printYN == 'N' ]
    then
        ufw allow cups
        ufw allow ipp
        ufw allow printer
    fi
    
    if [ $mysqlYN == 'y' ] || [ $mysqlYN == 'Y' ]
    then
        apt -y remove --purge mysql*
        apt -y purge mysql*
        ufw deny 3306
    elif [ $mysqlYN == 'n' ] || [ $mysqlYN == 'N' ]
    then
        ufw allow 3306
    fi

    if [ $httpYN == 'y' ] || [ $httpYN == 'Y' ]
    then
        ufw deny http
        ufw deny https
        apt -y purge apache2
    elif [ $httpYN == 'n' ] || [ $httpYN == 'N' ]
    then
        ufw allow http
        ufw allow https
        apt -y install apache2
    fi

    if [ $mediafilesYN == 'y' ] || [ $mediafilesYN == 'Y' ]
    then
        clear
        echo -e "Finding potentially-prohibited media files... Retrived items must be reviewed from the created \"mediaFileLocations.txt\" file and deleted, if necessary."        
        find / -iname "*.mp3" -o -iname "*.ogg" -o -iname "*.wav" -o -iname "*.mp4" -o -iname "*.mkv" -o -iname "*.webm" -o -iname "*.flv" -o -iname "*.mov" -o -iname "*.png" -o -iname "*.jpeg" -o -iname "*.jpg" -type f > mediaFileLocations.txt

        find /home -iname "*.mp3" -o -iname "*.ogg" -o -iname "*.wav" -o -iname "*.mp4" -o -iname "*.mkv" -o -iname "*.webm" -o -iname "*.flv" -o -iname "*.mov" -o -iname "*.png" -o -iname "*.jpeg" -o -iname "*.jpg" -type f > homeMediaFileLocations.txt
        echo "Media file query completed."
    fi

    apt-get -y autoremove
    apt-get -y autoclean
}

sanity_for_defaults () {
    # Secure bash history file
    echo "Securing bash history file"
    chmod 640 ~/.bash_history
}

various_tweaks () {
    # Remove all aliases
    echo "Removing all aliases"
    unalias -a
    # Install and update anti-virus 
    echo "Installing and updating clamav anti-virus"
    apt -y install clamav
    freshclam
    # Scan /home for infected items
    if [ $scanYN == 'y' ] || [ $scanYN == 'Y' ]
    then
        echo "Scanning /home as per user's preferences"
        clamscan -r /home
    fi
    echo "AdvHarden has now completed sucessfully"
    echo -e "\n\nPlease do the following now:"
    echo -e "  - Manually set PAM preferences"
    echo -e "  - Secure needed programs"
    echo -e "  - Check hosts file"
    echo -e "  - Check cron jobs"
    echo -e "  - Check and secure open ports with netstat ‐tulpn"
    echo -e "  - Manage startup programs"
    echo -e "  - Do an upgrade on all remaining packages"
    echo -e "  - Review mediaFileLocations.txt"
}

question_user () {
    read -p "Should SSH be removed from this image (y/n)? " sshYN
    read -p "Should Samba be removed from this image (y/n)? " sambaYN
    read -p "Should telnet be removed from this image (y/n)? " telnetYN
    read -p "Should NIS, Network Information Services, be removed from this image (y/n)? " nisYN
    read -p "Should rsh-server be removed from this image (y/n)? " rshYN
    read -p "Should vsftpd be removed from this image (y/n)? " vsftpdYN
    read -p "Should mail be removed from this image (y/n)? " mailYN
    read -p "Should printing capabilities be removed from this image (y/n)? " printYN
    read -p "Should MySQL be removed from this image (y/n)? " mysqlYN
    read -p "Should web server capabilities be removed from this image (y/n)? " httpYN
    read -p "Should tftpd-hpa, Trivial File Transfer Protocol, be removed from this image (y/n)? " tftpYN
    read -p "Are media files banned (y/n)? " mediafilesYN
    read -p "Should /home directory be scanned for infected items (y/n)? " scanYN

}

# Path to all users file argument
all_users_path="$1"
# Path to sudo users file argument
sudo_users_path="$2"

if [ "$all_users_path" == "help" ]
then
    echo "advharden"
    echo "A program to rapidly harden an Ubuntu Linux machine"
    echo "Usage: advharden [ALLUSERSPATH] [SUDOUSERSPATH]"
    echo ""
    echo -e "[ALLUSERSPATH]|The path to a user-defined file of all permitted users\n[SUDOUSERSPATH]|The path to a user-defined file of all permitted SUDO users" | column -tc "Option,Meaning" -s '|'
else
    echo -e "Welcome to AdvHarden-ub14\nCreated by Luke Blevins\nVersion 2019.0.1.4\n"
    echo "Disclaimer: It is advisable to complete any necessary forensics work first"
    read -p "Has all forensics work been completed (y/n)? " answer
    if [ $answer == 'y' ] || [ $answer == 'Y' ]
    then
        commence_hardening
    fi
fi

