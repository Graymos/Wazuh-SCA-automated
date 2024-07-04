#!/bin/bash

# Author: Grayson Mosley
# Automates hardening of systems through recommended SCA through wazuh (based off of a SCA)


## SSH

#Checks if SCA-script.conf file exists (will only happen this one time in the whole script, everything for ssh comes after this) and sets $file
file="/etc/ssh/sshd_config.d/SCA-script.conf"

if [ -f "$file" ]; then
    echo " - $file exists"
else
    echo " - Creating $file"
    touch "$file"
fi

#Ensure SSH access is limited. (restricted ssh access to sudoers, all unprivledged are unrestricted)
pattern="DenyGroups sudo"
if grep -q "DenyGroups sudo" "$file"; then
    echo " - Direct SSH access into sudo users already denied "
else
    echo " - Denying direct SSH access into sudo users"
    echo "#Denying direct SSH access to sudo users" >> "$file"
    echo "DenyGroups sudo" >> "$file"
fi

#Ensure SSH LogLevel is appropriate. (setting LogLevel to VERBOSE)
pattern="LogLevel VERBOSE"
if grep -q "LogLevel VERBOSE" "$file"; then
    echo " - LogLevel already VERBOSE"
else
    echo " - Setting LogLevel to VERBOSE"
    echo "" >> "$file"
    echo "#Setting LogLevel to VERBOSE so login and logout activity as well as the key fingerprint for any SSH key used for login will be logged" >> "$file"
    echo "LogLevel VERBOSE" >> "$file"
fi


#Proper root:root chown for sshd_config file and all files in sshd_config.d
chmod u-x,og-rwx /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config

while IFS= read -r -d $'\0' l_file; do
    if [ -e "$l_file" ]; then
        chmod u-x,og-rwx "$l_file"
        chown root:root "$l_file"
    fi
done < <(find /etc/ssh/sshd_config.d -type f -print0)

#Ensure permissions on SSH public host key files are configured.

l_pmask="0133"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"

awk '{print}' <<< "$(find -L /etc/ssh -xdev -type f -exec stat -Lc "%n %#a %U %G" {} +)" | (
    while read -r l_file l_mode l_owner l_group; do
        if file "$l_file" | grep -Pq ':\h+OpenSSH\h+(\H+\h+)?public\h+key\b'; then
            echo -e " - Checking private key file: \"$l_file\""
            if [ $(( l_mode & l_pmask )) -gt 0 ]; then
                echo -e " - File: \"$l_file\" is mode \"$l_mode\" changing to mode: \"$l_maxperm\""
                chmod u-x,go-wx "$l_file"
            fi
            if [ "$l_owner" != "root" ]; then
                echo -e " - File: \"$l_file\" is owned by: \"$l_owner\" changing owner to \"root\""
                chown root "$l_file"
            fi
            if [ "$l_group" != "root" ]; then
                echo -e " - File: \"$l_file\" is owned by group \"$l_group\" changing to group \"root\""
                chgrp "root" "$l_file"
            fi
        fi
    done
)
