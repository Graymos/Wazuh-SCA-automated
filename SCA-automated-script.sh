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
add_to_changes_count_func() { 
    changes_count=$((changes_count + 1))
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
        add_to_changes_count_func
    fi
}

## Function for checking perms and ownership (changing to root) of file
perms_ownership_check_func() {
    local l_maxperm="$1"
    local l_owner_parameter="$2"
    local l_group_parameter="$3"
    local l_dir="$4"
    local l_pmask="$( printf '%o' $(( 0777 & ~$l_maxperm)) )"
    l_pmask="0$l_pmask" # fixing so then it will be 4 digits instead of 3 with leading 0

    awk '{print}' <<< "$(find -L $l_dir -xdev -type f -exec stat -Lc "%n %#a %U %G" {} +)" | (
        while read -r l_file l_mode l_owner l_group; do
            echo -e " - Checking file permissions and user/group ownership: \"$l_file\""
            if [ $(( l_mode & l_pmask )) -gt 0 ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is mode \"$l_mode\" changing to mode: \"$l_maxperm\"${RESET}"
                chmod "$l_maxperm" "$l_file"
                error_check_func "Couldn't set permissions to \"$l_maxperm\" on \"$l_dir\""
                add_to_changes_count_func
            else
                echo -e "${GREEN} - Proper permissions for $l_file: already set to $l_mode${RESET}"
            fi
            if [ "$l_owner" != "$l_owner_parameter" ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is owned by: \"$l_owner\" changing owner to \"$l_owner_parameter\"${RESET}"
                chown "$l_owner_parameter" "$l_file"
                error_check_func "Couldn't set user ownership to \"l_owner_parameter\" on \"$l_dir\""
                add_to_changes_count_func
            else
                echo -e "${GREEN} - Proper user ownership for $l_file: already set to $l_owner${RESET}"
            fi
            if [ "$l_group" != "$l_group_parameter" ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is owned by group \"$l_group\" changing to group \"$l_group_parameter\"${RESET}"
                chgrp "$l_group_parameter" "$l_file"
                error_check_func "Couldn't set group ownership to \"$l_group_parameter\" on \"$l_dir\""
		add_to_changes_count_func
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
    echo -e " - Checking if file \"$l_file\" exists: "
    if [ -f "$l_file" ]; then
        echo -e "${GREEN} - $l_file exists${RESET}"
    else
        echo -e "${YELLOW} - Creating $l_file${RESET}"
        touch $l_file
        error_check_func "Couldn't create file: $l_file"
        add_to_changes_count_func
    fi
    return 0
}

## Checks if an app (package) is installed, if installed asks if needed and if not then uninstalls
uninstall_app_func() {
    local app="$1"
    local reason="$2"
    local answer='null'
    if which "$app" >/dev/null; then
        echo -e "${YELLOW} - \"$app\" is installed.${RESET}"
        echo -e "${YELLOW}Reason to uninstall \"$app\": ${RESET}${CYAN}$reason${RESET}"
        echo -e -n "${YELLOW}Uninstall? (default n) (y/n): ${RESET}"
        read answer
        answer=${answer,,}  # This converts answer to lowercase
        if [ $answer == 'y' ] 2>/dev/null; then
            add_to_changes_count_func
            apt purge "$app" -y
            error_check_func "Error uninstalling \"$app\""
            apt autoremove
            apt autoclean
        else
            echo -e "${YELLOW} - \"$app\" skipped.${RESET}"
        fi
    else
        echo -e "${GREEN} - \"$app\" isnt installed.${RESET}"
    fi
}

# --Start of ssh part of script--

## Check if script is running as root (UID 0)
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

## --SCA-script.conf added rules start here--

##File used for all added ssh config rules
ssh_file="/etc/ssh/sshd_config.d/SCA-script.conf"
echo " - Checking $ssh_file rules:"
## Ensure SSH access is limited. (restricted ssh access to sudoers, all unprivledged are unrestricted)
file_pattern_check_func "DenyGroups sudo" "$ssh_file"

## Ensure SSH LogLevel is appropriate. (setting LogLevel to VERBOSE)
file_pattern_check_func "LogLevel VERBOSE" "$ssh_file"

## Ensure SSH PAM is enabled.
file_pattern_check_func "UsePAM yes" "$ssh_file"

## Ensure SSH root login is disabled.
file_pattern_check_func "PermitRootLogin no" "$ssh_file"

## Ensure SSH HostbasedAuthentication is disabled.
file_pattern_check_func "HostbasedAuthentication no" "$ssh_file"

## Ensure SSH PermitEmptyPasswords is disabled.
file_pattern_check_func "PermitEmptyPasswords no" "$ssh_file"

## Ensure SSH PermitUserEnvironment is disabled.
file_pattern_check_func "PermitUserEnvironment no" "$ssh_file"

## Ensure SSH IgnoreRhosts is enabled.
file_pattern_check_func "IgnoreRhosts yes" "$ssh_file"

## Ensure SSH X11 forwarding is disabled.
file_pattern_check_func "X11Forwarding no" "$ssh_file"

## Ensure only strong Ciphers are used. (Only used FIPS 140-2 (potentially FIPS 140-3) compliant ciphers
file_pattern_check_func "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" "$ssh_file"

## Ensure only strong MAC algorithms are used.
file_pattern_check_func "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128-etm@openssh.com,umac-128@openssh.com" "$ssh_file"

## Ensure only strong Key Exchange algorithms are used.
file_pattern_check_func "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" "$ssh_file"

## Ensure SSH AllowTcpForwarding is disabled.
file_pattern_check_func "AllowTcpForwarding no" "$ssh_file"

## Ensure SSH warning banner is configured.
file_pattern_check_func "Banner /etc/issue.net" "$ssh_file"

## Ensure SSH MaxAuthTries is set to 4 or less.
file_pattern_check_func "MaxAuthTries 4" "$ssh_file"

## Ensure SSH MaxStartups is configured.
file_pattern_check_func "MaxStartups 10:30:60" "$ssh_file"

## Ensure SSH LoginGraceTime is set to one minute or less.
file_pattern_check_func "LoginGraceTime 60" "$ssh_file"

## Ensure SSH MaxSessions is set to 10 or less.
file_pattern_check_func "MaxSessions 10" "$ssh_file"

## Ensure SSH Idle Timeout Interval is configured.
file_pattern_check_func "ClientAliveInterval 15" "$ssh_file"
file_pattern_check_func "ClientAliveCountMax 3" "$ssh_file"

## --SCA-script.conf added rules ends here--

# Checking root user and group ownership and proper perms of files/all files in a dir (This and ensuring perms on pub/priv key files should be last 2 parts in SSH part of script)
perms_ownership_check_func "0600" "root" "root" "/etc/ssh/sshd_config"
perms_ownership_check_func "0600" "root" "root" "/etc/ssh/sshd_config.d"

## Ensure permissions on SSH public host key files are configured. (cant use function because added condition)
l_pmask="0133"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
awk '{print}' <<< "$(find -L /etc/ssh -xdev -type f -exec stat -Lc "%n %#a %U %G" {} +)" | (
    while read -r l_file l_mode l_owner l_group; do
        if file "$l_file" | grep -Pq ':\h+OpenSSH\h+(\H+\h+)?$type-of-ssh-key-file\h+key\b'; then ## (added condition)
            echo -e " - Checking public key file: \"$l_file\""
            if [ $(( l_mode & l_pmask )) -gt 0 ]; then
                echo -e "${YELLOW} - File: \"$l_file\" is mode \"$l_mode\" changing to mode: \"$l_maxperm\"${RESET}"
                chmod "$l_maxperm" "$l_file"
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

## Restarting ssh if changes made so applies new rules

if [ $changes_count -ne 0 ]; then
    systemctl reload ssh
    echo "Pausing for 10 seconds to let ssh reload"
    sleep 1
    reset_changes_count_func
fi

# --SSH ends here--

## Checks if root user has password
echo " - Checking root password"
if [ "$(grep '^root:' '/etc/shadow' | cut -d: -f2)" != "*" ]
then
    echo -e "${GREEN} - Root password appears to be set${RESET}"
else
    echo -e "${YELLOW} - Root password may be disabled or not set (empty password hash):${RESET}"
    passwd root
    error_check_func "Couldn't set root passwd"
    add_to_changes_count_func
fi

## Ensure message of the day is configured properly.
echo " - Checking /etc/issue.net"
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
echo " - Checking /etc/motd (removing)"
if test -f /etc/motd; then
    rm /etc/motd
    error_check_func "Failed to remove /etc/motd"
    echo -e "${YELLOW} - Removed /etc/motd${RESET}"
else
    echo -e "${GREEN} - /etc/motd already non-existent${RESET}"
fi

## Ensure local login warning banner is configured properly
echo " - Checking /etc/issue"
if test -f /etc/issue; then
   if grep -q "Authorized use only. All activity may be monitored and reported." "/etc/issue"; then
        file_pattern_check_func "Authorized use only. All activity may be monitored and reported." "/etc/issue"
   else
        file_pattern_check_func "Authorized use only. All activity may be monitored and reported." "/etc/issue"
        echo "Authorized use only. All activity may be monitored and reported." > "/etc/issue"
   fi
fi

## Ensure permissions on /etc/issue are configured.
perms_ownership_check_func "0644" "root" "root" "/etc/issue"


## Ensure permissions on /etc/issue.net are configured.
perms_ownership_check_func "0644" "root" "root" "/etc/issue.net"

# Checking all apps that shouldnt (for security reasons) be installed unless needed because of increasing attack surface
echo " - Checking applications to reduce the attack surface (not necessarily insecure but it can increase attack surface)"
## Ensure X Window System is not installed
uninstall_app_func "xserver-xorg" "The X Window System provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on. The X Windows system is typically used on workstations where users login, but not on servers where users typically do not login. Unless your organization specifically requires graphical login access via X Windows, remove it to reduce the potential attack surface."

## Ensure telnet client is not installed.
uninstall_app_func "telnet" "The telnet package contains the telnet client, which allows users to start connections to other systems via the telnet protocol. The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow an unauthorized user to steal credentials. The ssh package provides an encrypted session and stronger security and is included in most Linux distributions."

## Ensure Avahi Server is not installed.
uninstall_app_func "avahi-daemon" "Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers to print to, files to look at and people to talk to, as well as network services running on the machine. Automatic discovery of network services is not normally required for system functionality. It is recommended to remove this package to reduce the potential attack surface."

## Ensure CUPS is not installed.
uninstall_app_func "cups" "The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers. It also provides a web based remote administration capability. If the system does not need to print jobs or accept print jobs from other systems, it is recommended that CUPS be removed to reduce the potential attack surface."

## Ensure DHCP Server is not installed.
uninstall_app_func "isc-dhcp-server" "The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses. Unless a system is specifically set up to act as a DHCP server, it is recommended that this package be removed to reduce the potential attack surface."

## Ensure LDAP server is not installed.
uninstall_app_func "slapd" "The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database. If the system will not need to act as an LDAP server, it is recommended that the software be removed to reduce the potential attack surface."

## Ensure NFS is not installed
uninstall_app_func "nfs-kernel-server" "The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network. If the system does not export NFS shares, it is recommended that the nfs-kernel-server package be removed to reduce the remote attack surface."

## Ensure DNS Server is not installed.
uninstall_app_func "bind9" "The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses for computers, services and other resources connected to a network. Unless a system is specifically designated to act as a DNS server, it is recommended that the package be deleted to reduce the potential attack surface."

## Ensure FTP Server is not installed.
uninstall_app_func "vsftpd" "The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files. FTP does not protect the confidentiality of data or authentication credentials. It is recommended SFTP be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the package be deleted to reduce the potential attack surface."

## Ensure HTTP server is not installed.
uninstall_app_func "apache2" "HTTP or web servers provide the ability to host web site content. Unless there is a need to run the system as a web server, it is recommended that the package be deleted to reduce the potential attack surface."

## Ensure IMAP and POP3 server are not installed.
uninstall_app_func "dovecot-imapd" "dovecot-imapd and dovecot-pop3d are an open source IMAP and POP3 server for Linux based systems. Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the package be removed to reduce the potential attack surface."
uninstall_app_func "dovecot-pop3d" "dovecot-imapd and dovecot-pop3d are an open source IMAP and POP3 server for Linux based systems. Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the package be removed to reduce the potential attack surface."

## Ensure Samba is not installed.
uninstall_app_func "samba" "The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Server Message Block (SMB) protocol. Windows desktop users will be able to mount these directories and file systems as letter drives on their systems. If there is no need to mount directories and file systems to Windows systems, then this service should be deleted to reduce the potential attack surface."

## Ensure HTTP Proxy Server is not installed.
uninstall_app_func "squid" "Squid is a standard proxy server used in many distributions and environments. If there is no need for a proxy server, it is recommended that the squid proxy be deleted to reduce the potential attack surface."

## Ensure SNMP Server is not installed.
uninstall_app_func "snmpd" "Simple Network Management Protocol (SNMP) is a widely used protocol for monitoring the health and welfare of network equipment, computer equipment and devices like UPSs. Net-SNMP is a suite of applications used to implement SNMPv1 (RFC 1157), SNMPv2 (RFCs 1901-1908), and SNMPv3 (RFCs 3411-3418) using both IPv4 and IPv6. Support for SNMPv2 classic (a.k.a. "SNMPv2 historic" - RFCs 1441-1452) was dropped with the 4.0 release of the UCD-snmp package. The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management system, execute the commands or collect the information and then send results back to the requesting system. The SNMP server can communicate using SNMPv1, which transmits data in the clear and does not require authentication to execute commands. SNMPv3 replaces the simple/clear text password sharing used in SNMPv2 with more securely encoded parameters. If the the SNMP service is not required, the snmpd package should be removed to reduce the attack surface of the system. Note: If SNMP is required: - The server should be configured for SNMP v3 only. User Authentication and Message Encryption should be configured. If SNMP v2 is absolutely necessary, modify the community strings' values. -."

## Ensure NIS Server is not installed.
uninstall_app_func "nis" "The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server directory service protocol for distributing system configuration files. The NIS server is a collection of programs that allow for the distribution of configuration files. The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed and other, more secure services be used."

## Ensure dnsmasq is not installed.
uninstall_app_func "dnsmasq" "dnsmasq is a lightweight tool that provides DNS caching, DNS forwarding and DHCP (Dynamic Host Configuration Protocol) services. Unless a system is specifically designated to act as a DNS caching, DNS forwarding and/or DHCP server, it is recommended that the package be removed to reduce the potential attack surface."

## 
