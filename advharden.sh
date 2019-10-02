#!/bin/bash

commence_hardening () {
    countdown
	tput reset
    compare_users
    enable_firewall
    disable_guest
   # password_policy
   # password_history
    account_lockout
    audit_policy
	hacking_tools
	enable_AppArmor
	stig_complicance_measures
	
}

countdown () {
    echo "Program will proceed with Ubuntu hardening in 5000 ms"
    for((i=5;i>0;i--));
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
            read -p "Promote admin user ${allowed_user} (y/n)? " answer
            if [ $answer == 'y' ] || [ $answer == 'Y' ]
            then
                gpasswd -a ${allowed_user} sudo
            fi
        fi
    done
}

enable_firewall () {
    echo "Enabling ufw with default rule set"
    ufw enable
}

disable_guest () {
    file_to_test="/etc/lightdm/lightdm.conf.d/50-no-guest.conf"
    if [ -f "$file_to_test" ]
    then
		echo "Guest account already disabled"
    else
    	echo "Disabling guest account"
    	sh -c 'printf "[SeatDefaults]\nallow-guest=false\n" >/etc/lightdm/lightdm.conf.d/50-no-guest.conf'
    fi

}

password_policy () {
    echo "Configuring password length and complexity"

    line_num="$(grep -nr "pam_unix.so" /etc/pam.d/common-password | cut -d : -f 1)"
    line_text="$(grep "pam_unix.so" /etc/pam.d/common-password)"
    text_to_append=" remember=5 minlen=8"
    if [ $line_text != *"remember"* ] || [ $line_text != *"minlen"* ]
    then
        sed -i "${line_num}a ${text_to_append}" /etc/pam.d/common-password
    else
        echo "Error: Configuration file common-password requires manual review for pam_unix.so"
    fi

    line_num="$(grep -nr "pam_cracklib.so" /etc/pam.d/common-password | cut -d : -f 1)"
    line_text="$(grep "pam_cracklib.so" /etc/pam.d/common-password)"
    text_to_append=" ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"
    if [[ $line_text != *"credit"* ]]
    then
        sed -i "${line_num}a ${text_to_append}" /etc/pam.d/common-password
    else
        echo "Error: Configuration file common-password requires manual review for pam_cracklib.so"
    fi
}

password_history () {
    echo "Configuring password history variables"
    line_num=$(grep -nr "PASS_MAX_DAYS" /etc/login.defs | cut -d : -f 1 | cut -d$'\n' -f 2)
    line_text=$(grep "PASS_MAX_DAYS" /etc/login.defs)
    text_to_add=$"PASS_MAX_DAYS\t90"
    #sed -i "${line_num}i ${text_to_add}" /etc/login.defs
    sed -i "${line_num}s/${line_text}/${text_to_add}/" /etc/login.defs

    line_num="$(grep -nr "PASS_MIN_DAYS" /etc/login.defs | cut -d : -f 1)"
    text_to_add="PASS_MIN_DAYS    10"
    sed -i "${line_num}i ${text_to_add}" /etc/login.defs

    line_num="$(grep -nr "PASS_WARN_AGE" /etc/login.defs | cut -d : -f 1)"
    text_to_add="PASS_WARN_AGE    7"
    sed -i "${line_num}i ${text_to_add}" /etc/login.defs

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
	apt -y install apparmor
	systemctl enable apparmor
	systemctl start apparmor
}

stig_complicance_measures () {
	# Allow user initiation of session locks
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
	passwd -l root
	# Account identifiers
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
	
}

question_user () {
    read -p "Should all programs on this machine be upgraded (y/n)? " upgradeYN

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
    echo -e "Welcome to AdvHarden\nCreated by Luke Blevins\nVersion 2019.0.0.2\n"
    echo "Disclaimer: It is advisable to complete forensics questions first"
    read -p "Have the forensics questions been completed (y/n)? " answer
    if [ $answer == 'y' ] || [ $answer == 'Y' ]
    then
        commence_hardening
    fi
fi

