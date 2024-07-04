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

echo -e "${CYAN}All sshd_config settings that this script makes is in /etc/ssh/sshd_config.d/SCA-script.conf so if any settings are conflicting with needed purpose of machine, this is where you would modify settings${RESET}"
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
ssh_function() {
    local pattern="$1"
    if grep -q "$pattern" "$file"; then
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
ssh_function "DenyGroups sudo"

## Ensure SSH LogLevel is appropriate. (setting LogLevel to VERBOSE)
ssh_function "LogLevel VERBOSE"

## Ensure SSH PAM is enabled.
ssh_function "UsePAM yes"

## Ensure SSH root login is disabled.
ssh_function "PermitRootLogin no"

## 

### After this point it deals with everything outside of SCA-script.conf
### Needs cleanup and to be made into a function that automatically searches a folder/file perms and user/group ownership and correct them to function parameters

## Proper root:root user and group ownership and proper perms for sshd_config file (This and ensuring perms on pub host key files should be last 2 in SSH part of script)
l_pmask="0177"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask)) )"

awk '{print}' <<< "$(find -L /etc/ssh/sshd_config -xdev -type f -exec stat -Lc "%n %#a %U %G" {} +)" | (
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


## Proper root:root user and group ownership and proper perms for all files in sshd_config.d dir (This and ensuring perms on pub host key files should be last 2 in SSH part of script)
l_pmask="0177"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask)) )"
awk '{print}' <<< "$(find -L /etc/ssh/sshd_config.d -xdev -type f -exec stat -Lc "%n %#a %U %G" {} +)" | (
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
## Ensure permissions on SSH public host key files are configured.

l_pmask="0133"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"

awk '{print}' <<< "$(find -L /etc/ssh -xdev -type f -exec stat -Lc "%n %#a %U %G" {} +)" | (
    while read -r l_file l_mode l_owner l_group; do
        if file "$l_file" | grep -Pq ':\h+OpenSSH\h+(\H+\h+)?public\h+key\b'; then
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
