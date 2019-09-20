#!/bin/bash

commence_hardening () {
    countdown
    compare_users
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

