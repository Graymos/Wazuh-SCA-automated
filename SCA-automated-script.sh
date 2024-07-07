#!/bin/bash

# Author: Grayson Mosley
# Automates hardening of systems through recommended SCA through wazuh (based off of a SCA)

#Colors for echo
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[38;5;226m'
BLUE='\e[34m'
MAGENTA='\e[35m'
CYAN='\e[36m'
RESET='\e[0m'



# Global vars
total_changes_count=0
changes_count=0 # int to see if/how many changes are made

# Functions
reset_changes_count_func() {
    total_changes_count=$((changes_count + total_changes_count))
    changes_count=0
}
add_to_changes_count_func() { #uses return code of 5 (custom to my own functions) or if parameter == 5 then will add to count_changes
    local changes_exit_code=$?
    local inputted_error_code="$1"
    if [[ $changes_exit_code -eq 5 || $inputted_error_code -eq 5 ]]; then
        changes_count=$((changes_count + 1))
    fi
    return 0
}
error_check_func() {
    local exit_code=$?
    local message="$1"
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}Error:${RESET} $message"
        return 1 #returns 1 means is an error
    fi
    return 0 
}

## Function that checks a file for a pattern and adds the specified pattern to file if not found
file_pattern_check_func() {
    local pattern="$1"
    local file="$2"
    if grep -q "$pattern" "$file"; then
        if [ $? -ne 0 ]; then
            echo -e "${RED}Error:${RESET} Command failed for searching for \"$pattern\" in $file."
            exit 1
        fi
        echo -e "${GREEN} - \"$pattern\" rule already set in $file${RESET}"
    else
        echo -e "${YELLOW} - Adding \"$pattern\" rule in $file${RESET}"
        echo -e "$pattern" >> "$file"
        if [ $? -ne 0 ]; then
            echo -e "${RED}Error:${RESET} Command failed for appending rule \"$pattern\" to $file."
            exit 1
        fi
        return 5 # return 5 so that add_to_changes_count_func can be used after
    fi
}

## Function for checking perms and ownership (changing to root) of file
perms_ownership_check_func() {
    local l_pmask="$1"
    local l_dir="$2"
    local l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask)) )"

    awk '{print}' <<< "$(find -L $l_dir -xdev -type f -exec stat -Lc "%n %#a %U %G" {} +)" | (
        while read -r l_file l_mode l_owner l_group; do
            echo -e " - Checking file: \"$l_file\""
            if [ $(( l_mode & l_pmask )) -gt 0 ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is mode \"$l_mode\" changing to mode: \"$l_maxperm\"${RESET}"
                chmod u-x,og-rwx "$l_file"
            else
                echo -e "${GREEN} - Proper permissions for $l_file: already set to $l_mode${RESET}"
            fi
            if [ "$l_owner" != "root" ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is owned by: \"$l_owner\" changing owner to \"root\"${RESET}"
                chown root "$l_file"
            else
                echo -e "${GREEN} - Proper user ownership for $l_file: already set to $l_owner${RESET}"
            fi
            if [ "$l_group" != "root" ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is owned by group \"$l_group\" changing to group \"root\"${RESET}"
                chgrp "root" "$l_file"
            else
                echo -e "${GREEN} - Proper group ownership for $l_file: already set to $l_group${RESET}"
            fi
        done
    )
    return 0
}

## Checks if a file exists, if it doesnt then creates it
file_exist_func() {
    local l_file="$1"
    echo -e " - Checking if file exists: "
    if [ -f "$l_file" ]; then
        echo -e "${GREEN} - $l_file exists${RESET}"
    else
        echo -e "${YELLOW} - Creating $l_file${RESET}"
        touch $l_file
        error_check_func "Couldn't create file: $l_file"
        return 5
    fi
    return 0
}

# --Start of script--

# Check if script is running as root (UID 0)
if [ "$UID" -eq 0 ]
then
    echo -e ""
else
    echo -e "${RED}Script requires root privileges${RESET}"
    exit 1  # Exit with an error code
fi

# SSH
echo -e "${CYAN}SSH:\n   All sshd_config settings that this script makes is in /etc/ssh/sshd_config.d/SCA-script.conf so if any settings are conflicting with needed purpose of machine, this is where you would modify settings${RESET}"

## Checks if SCA-script.conf file exists and creates it if it doesnt
file_exist_func "/etc/ssh/sshd_config.d/SCA-script.conf"
add_to_changes_count_func
## --SCA-script.conf added rules start here--

##File used for all added ssh config rules
ssh_file="/etc/ssh/sshd_config.d/SCA-script.conf"

## Ensure SSH access is limited. (restricted ssh access to sudoers, all unprivledged are unrestricted)
file_pattern_check_func "DenyGroups sudo" "$ssh_file"
add_to_changes_count_func

## Ensure SSH LogLevel is appropriate. (setting LogLevel to VERBOSE)
file_pattern_check_func "LogLevel VERBOSE" "$ssh_file"
add_to_changes_count_func
## Ensure SSH PAM is enabled.
file_pattern_check_func "UsePAM yes" "$ssh_file"
add_to_changes_count_func
## Ensure SSH root login is disabled.
file_pattern_check_func "PermitRootLogin no" "$ssh_file"
add_to_changes_count_func
## Ensure SSH HostbasedAuthentication is disabled.
file_pattern_check_func "HostbasedAuthentication no" "$ssh_file"
add_to_changes_count_func
## Ensure SSH PermitEmptyPasswords is disabled.
file_pattern_check_func "PermitEmptyPasswords no" "$ssh_file"
add_to_changes_count_func
## Ensure SSH PermitUserEnvironment is disabled.
file_pattern_check_func "PermitUserEnvironment no" "$ssh_file"
add_to_changes_count_func
## Ensure SSH IgnoreRhosts is enabled.
file_pattern_check_func "IgnoreRhosts yes" "$ssh_file"
add_to_changes_count_func
## Ensure SSH X11 forwarding is disabled.
file_pattern_check_func "X11Forwarding no" "$ssh_file"
add_to_changes_count_func
## Ensure only strong Ciphers are used. (Only used FIPS 140-2 (potentially FIPS 140-3) compliant ciphers
file_pattern_check_func "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" "$ssh_file"
add_to_changes_count_func
## Ensure only strong MAC algorithms are used.
file_pattern_check_func "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128-etm@openssh.com,umac-128@openssh.com" "$ssh_file"
add_to_changes_count_func
## Ensure only strong Key Exchange algorithms are used.
file_pattern_check_func "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" "$ssh_file"
add_to_changes_count_func
## Ensure SSH AllowTcpForwarding is disabled.
file_pattern_check_func "AllowTcpForwarding no" "$ssh_file"
add_to_changes_count_func
## Ensure SSH warning banner is configured.
file_pattern_check_func "Banner /etc/issue.net" "$ssh_file"
add_to_changes_count_func
## Ensure SSH MaxAuthTries is set to 4 or less.
file_pattern_check_func "MaxAuthTries 4" "$ssh_file"
add_to_changes_count_func
## Ensure SSH MaxStartups is configured.
file_pattern_check_func "MaxStartups 10:30:60" "$ssh_file"
add_to_changes_count_func
## Ensure SSH LoginGraceTime is set to one minute or less.
file_pattern_check_func "LoginGraceTime 60" "$ssh_file"
add_to_changes_count_func
## Ensure SSH MaxSessions is set to 10 or less.
file_pattern_check_func "MaxSessions 10" "$ssh_file"
add_to_changes_count_func
## Ensure SSH Idle Timeout Interval is configured.
file_pattern_check_func "ClientAliveInterval 15" "$ssh_file"
add_to_changes_count_func
file_pattern_check_func "ClientAliveCountMax 3" "$ssh_file"
add_to_changes_count_func
## --SCA-script.conf added rules ends here--

# Checking root user and group ownership and proper perms of files/all files in a dir (This and ensuring perms on pub/priv key files should be last 2 parts in SSH part of script)
perms_ownership_check_func "0177" "/etc/ssh/sshd_config"
perms_ownership_check_func "0177" "/etc/ssh/sshd_config.d"

## Ensure permissions on SSH public host key files are configured. (cant use function because added condition)
l_pmask="0133"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
awk '{print}' <<< "$(find -L /etc/ssh -xdev -type f -exec stat -Lc "%n %#a %U %G" {} +)" | (
    while read -r l_file l_mode l_owner l_group; do
        if file "$l_file" | grep -Pq ':\h+OpenSSH\h+(\H+\h+)?$type-of-ssh-key-file\h+key\b'; then ## (added condition)
            echo -e " - Checking public key file: \"$l_file\""
            if [ $(( l_mode & l_pmask )) -gt 0 ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is mode \"$l_mode\" changing to mode: \"$l_maxperm\"${RESET}"
                chmod u-x,go-wx "$l_file"
            else
                echo -e "${GREEN} - Proper permissions for $l_file: already set to $l_mode${RESET}"
            fi
            if [ "$l_owner" != "root" ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is owned by: \"$l_owner\" changing owner to \"root\"${RESET}"
                chown root "$l_file"
            else
                echo -e "${GREEN} - Proper user ownership for $l_file: already set to $l_owner${RESET}"
            fi
            if [ "$l_group" != "root" ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is owned by group \"$l_group\" changing to group \"root\"${RESET}"
                chgrp "root" "$l_file"
            else
                 echo -e "${GREEN} - Proper group ownership for $l_file: already set to $l_group${RESET}"
            fi
        fi
    done
)

## Ensure permissions on SSH private host key files are configured. (cant use function because added condition)
l_pmask="0377"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
awk '{print}' <<< "$(find -L /etc/ssh -xdev -type f -exec stat -Lc "%n %#a %U %G" {} +)" | (
    while read -r l_file l_mode l_owner l_group; do
        if file "$l_file" | grep -Pq ':\h+OpenSSH\h+(\H+\h+)?private\h+key\b'; then ## (added condition)
            echo -e " - Checking private key file: \"$l_file\""
            if [ $(( l_mode & l_pmask )) -gt 0 ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is mode \"$l_mode\" changing to mode: \"$l_maxperm\"${RESET}"
                chmod 400 "$l_file"
            else
                echo -e "${GREEN} - Proper permissions for $l_file: already set to $l_mode${RESET}"
            fi
            if [ "$l_owner" != "root" ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is owned by: \"$l_owner\" changing owner to \"root\"${RESET}"
                chown root "$l_file"
            else
                echo -e "${GREEN} - Proper user ownership for $l_file: already set to $l_owner${RESET}"
            fi
            if [ "$l_group" != "root" ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is owned by group \"$l_group\" changing to group \"root\"${RESET}"
                chgrp "root" "$l_file"
            else
                echo -e "${GREEN} - Proper group ownership for $l_file: already set to l_group${RESET}"
            fi
        fi
    done
)

##restarting ssh if changes made so applies new rules

if [ $changes_count -ne 0 ]; then
    systemctl restart ssh
    echo "Pausing for 10 seconds to let ssh restart"
    sleep 1
    reset_changes_count_func
fi

# --SSH ends here--

# Checks if root user has password
echo " - Checking root password"
if [ "$(grep '^root:' '/etc/shadow' | cut -d: -f2)" != "*" ]
then
    echo -e "${GREEN} - Root password appears to be set${RESET}"
else
    echo -e "${YELLOW} - Root password may be disabled or not set (empty password hash):${RESET}"
    passwd root
    error_check_func "Couldn't set root passwd"
fi

# Ensure message of the day is configured properly.
echo " - Checking MOTD (removing /etc/motd and using /etc/issue.net instead)"
if test -f /etc/issue.net; then
    if grep -q "Authorized use only. All activity may be monitored and reported." "/etc/issue.net"; then
        file_pattern_check_func "Authorized use only. All activity may be monitored and reported." "/etc/issue.net"
    else
        rm /etc/issue.net
        error_check_func "Couldn't remove /etc/issue.net (to make new file to have new message)"
        touch /etc/issue.net
        error_check_func "Couldn't create /etc/issue.net"
        file_pattern_check_func "Authorized use only. All activity may be monitored and reported." "/etc/issue.net"
    fi
fi

## Using issue.net, dont need motd so removes it
if test -f /etc/motd; then
    rm /etc/motd
    error_check_func "Failed to remove /etc/motd"
    echo -e "${YELLOW} - Removed /etc/motd${RESET}"
else
    echo -e "${GREEN} - /etc/motd already non-existent${RESET}"
fi

# 
