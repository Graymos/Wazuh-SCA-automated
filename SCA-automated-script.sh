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

# SSH

echo -e "${CYAN}SSH:\n   All sshd_config settings that this script makes is in /etc/ssh/sshd_config.d/SCA-script.conf so if any settings are conflicting with needed purpose of machine, this is where you would modify settings${RESET}"
## Checks if SCA-script.conf file exists (will only happen this one time in the whole script, everything for ssh comes after this) and sets $file
file="/etc/ssh/sshd_config.d/SCA-script.conf"
echo -e " - Checking file for SSH rules: $file"
if [ -f "$file" ]; then
    echo -e "${GREEN} - $file exists${RESET}"
else
    echo -e "${YELLOW} - Creating $file${RESET}"
    touch "$file"
    echo -e "#sshd config file created by SCA-automated-script.sh which creates settings to harden a debian based machine's ssh settings" >> "$file"
    echo -e "" >> "$file"
fi

## Function that ssh SCA checks and modifications use for file /etc/ssh/sshd_config.d/SCA-script.conf
sca_script_config_function() {
    local pattern="$1"
    if grep -q "$pattern" "$file"; then
        if [ $? -ne 0 ]; then
            echo -e "${RED}Error:${RESET} Command failed for searching for \"$pattern\" in $file."
        fi
        echo -e "${GREEN} - \"$pattern\" rule already set in $file${RESET}"
    else
        echo -e "${YELLOW} - Adding \"$pattern\" rule in $file${RESET}"
        echo -e "$pattern" >> "$file"
        if [ $? -ne 0 ]; then
            echo -e "${RED}Error:${RESET} Command failed for appending rule \"$pattern\" to $file."
        fi
    fi

}


## Ensure SSH access is limited. (restricted ssh access to sudoers, all unprivledged are unrestricted)
sca_script_config_function "DenyGroups sudo"

## Ensure SSH LogLevel is appropriate. (setting LogLevel to VERBOSE)
sca_script_config_function "LogLevel VERBOSE"

## Ensure SSH PAM is enabled.
sca_script_config_function "UsePAM yes"

## Ensure SSH root login is disabled.
sca_script_config_function "PermitRootLogin no"

## Ensure SSH HostbasedAuthentication is disabled.
sca_script_config_function "HostbasedAuthentication no"

## Ensure SSH PermitEmptyPasswords is disabled.
sca_script_config_function "PermitEmptyPasswords no"

## Ensure SSH PermitUserEnvironment is disabled.
sca_script_config_function "PermitUserEnvironment no"

## Ensure SSH IgnoreRhosts is enabled.
sca_script_config_function "IgnoreRhosts yes"

## Ensure SSH X11 forwarding is disabled.
sca_script_config_function "X11Forwarding no"

## Ensure only strong Ciphers are used. (Only used FIPS 140-2 (potentially FIPS 140-3) compliant ciphers
sca_script_config_function "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"

## Ensure only strong MAC algorithms are used.
sca_script_config_function "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128-etm@openssh.com,umac-128@openssh.com"

## Ensure only strong Key Exchange algorithms are used.
sca_script_config_function "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"

## Ensure SSH AllowTcpForwarding is disabled.
sca_script_config_function "AllowTcpForwarding no"

## Ensure SSH warning banner is configured.
sca_script_config_function "Banner /etc/issue.net"

## Ensure SSH MaxAuthTries is set to 4 or less.
sca_script_config_function "MaxAuthTries 4"

## Ensure SSH MaxStartups is configured.
sca_script_config_function "MaxStartups 10:30:60"

## Ensure SSH LoginGraceTime is set to one minute or less.
sca_script_config_function "LoginGraceTime 60"

## Ensure SSH MaxSessions is set to 10 or less.
sca_script_config_function "MaxSessions 10"

## Ensure SSH Idle Timeout Interval is configured.
sca_script_config_function "ClientAliveInterval 15"
sca_script_config_function "ClientAliveCountMax 3"

### Everything after this point deals with everything outside of SCA-script.conf
### Needs cleanup and to be made into a function that automatically searches a folder/file perms and user/group ownership and correct them to function parameters

## checking perms and ownership (changing to root) of file
perms_ownership_check() {
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
}

## Checking root user and group ownership and proper perms of files/all files in a dir (This and ensuring perms on pub/priv key files should be last 2 parts in SSH part of script)
perms_ownership_check "0177" "/etc/ssh/sshd_config"
perms_ownership_check "0177" "/etc/ssh/sshd_config.d"

## Ensure permissions on SSH public host key files are configured.
l_pmask="0133"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
awk '{print}' <<< "$(find -L /etc/ssh -xdev -type f -exec stat -Lc "%n %#a %U %G" {} +)" | (
    while read -r l_file l_mode l_owner l_group; do
        if file "$l_file" | grep -Pq ':\h+OpenSSH\h+(\H+\h+)?$type-of-ssh-key-file\h+key\b'; then
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

## Ensure permissions on SSH private host key files are configured.
l_pmask="0377"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
awk '{print}' <<< "$(find -L /etc/ssh -xdev -type f -exec stat -Lc "%n %#a %U %G" {} +)" | (
    while read -r l_file l_mode l_owner l_group; do
        if file "$l_file" | grep -Pq ':\h+OpenSSH\h+(\H+\h+)?private\h+key\b'; then
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
