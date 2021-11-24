#!/bin/sh -

# WARNING: Changes to this file in the salt repo will be overwritten!
# Please submit pull requests against the salt-bootstrap repo:
# https://github.com/saltstack/salt-bootstrap

#======================================================================================================================
# vim: softtabstop=4 shiftwidth=4 expandtab fenc=utf-8 spell spelllang=en cc=120
#======================================================================================================================
#
#          FILE: se-install.sh
#
#   DESCRIPTION: Bootstrap Salt installation for various systems/distributions
#
#          BUGS: https://github.com/saltstack/salt-bootstrap/issues
#
#     COPYRIGHT: (c) 2012-2018 by the SaltStack Team, see AUTHORS.rst for more
#                details.
#
#       LICENSE: Apache 2.0
#  ORGANIZATION: VCS (Viettel Cyber Security)
#       CREATED: 09/10/2019 10:30:37 AM WEST
#======================================================================================================================


set -o nounset
__ScriptVersion="2017.7.36"
__ScriptName="se-install.sh"

__ScriptFullName="$0"
__ScriptArgs="$*"


#======================================================================================================================
#  Environment variables taken into account.
#----------------------------------------------------------------------------------------------------------------------
#   * BS_COLORS:                If 0 disables colour support
#   * BS_PIP_ALLOWED:           If 1 enable pip based installations(if needed)
#   * BS_PIP_ALL:               If 1 enable all python packages to be installed via pip instead of apt, requires setting virtualenv
#   * BS_VIRTUALENV_DIR:        The virtualenv to install salt into (shouldn't exist yet)
#   * BS_ECHO_DEBUG:            If 1 enable debug echo which can also be set by -D
#   * BS_SALT_ETC_DIR:          Defaults to /etc/salt (Only tweak'able on git based installations)
#   * BS_SALT_CACHE_DIR:        Defaults to /var/cache/salt (Only tweak'able on git based installations)
#   * BS_KEEP_TEMP_FILES:       If 1, don't move temporary files, instead copy them
#   * BS_FORCE_OVERWRITE:       Force overriding copied files(config, init.d, etc)
#   * BS_UPGRADE_SYS:           If 1 and an option, upgrade system. Default 0.
#   * BS_GENTOO_USE_BINHOST:    If 1 add `--getbinpkg` to gentoo's emerge
#   * BS_SALT_MASTER_ADDRESS:   The IP or DNS name of the salt-master the minion should connect to
#   * BS_SALT_GIT_CHECKOUT_DIR: The directory where to clone Salt on git installations
#======================================================================================================================

# Bootstrap script truth values
BS_TRUE=1
BS_FALSE=0

# Default sleep time used when waiting for daemons to start, restart and checking for these running
__DEFAULT_SLEEP=5

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __detect_color_support
#   DESCRIPTION:  Try to detect color support.
#----------------------------------------------------------------------------------------------------------------------
_COLORS=${BS_COLORS:-$(tput colors 2>/dev/null || echo 0)}
__detect_color_support() {
    # shellcheck disable=SC2181
    if [ $? -eq 0 ] && [ "$_COLORS" -gt 2 ]; then
        RC='\033[1;31m'
        GC='\033[1;32m'
        BC='\033[1;34m'
        YC='\033[1;33m'
        EC='\033[0m'
    else
        RC=""
        GC=""
        BC=""
        YC=""
        EC=""
    fi
}
__detect_color_support

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  echoerr
#   DESCRIPTION:  Echo errors to stderr.
#----------------------------------------------------------------------------------------------------------------------
echoerror() {
    printf "${RC} * ERROR${EC}: %s\\n" "$@" 1>&2;
}

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  echoinfo
#   DESCRIPTION:  Echo information to stdout.
#----------------------------------------------------------------------------------------------------------------------
echoinfo() {
    printf "${GC} *  INFO${EC}: %s\\n" "$@";
}

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  echowarn
#   DESCRIPTION:  Echo warning information to stdout.
#----------------------------------------------------------------------------------------------------------------------
echowarn() {
    printf "${YC} *  WARN${EC}: %s\\n" "$@";
}

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  echodebug
#   DESCRIPTION:  Echo debug information to stdout.
#----------------------------------------------------------------------------------------------------------------------
echodebug() {
    if [ "$_ECHO_DEBUG" -eq $BS_TRUE ]; then
        printf "${BC} * DEBUG${EC}: %s\\n" "$@";
    fi
}

#----------------------------------------------------------------------------------------------------------------------
#  Handle command line arguments
#----------------------------------------------------------------------------------------------------------------------
_ECHO_DEBUG=${BS_ECHO_DEBUG:-$BS_FALSE}
_SALT_ETC_DIR=${BS_SALT_ETC_DIR:-/etc/salt}
_VAR_CACHE_SALT=${VAR_CACHE_SALT:-/var/cache/salt/}
_INSTALL_DIR=${_INSTALL_DIR:-/opt/se}
_FORCE_INSTALL=$BS_FALSE
_INSTALL_FILEBEAT=$BS_TRUE
_SALT_ID_SUBNET=${SALT_ID_SUBNET:-null}
__PRIMARY_IP=null
_SLEEP="${__DEFAULT_SLEEP}"
_METHOD_TRANSFER="curl"
_TMP_DIR=${TMP_DIR:-/tmp/se}
_VALIDATE_SERVER_ID=$BS_TRUE

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  in subnet
#   DESCRIPTION:
#----------------------------------------------------------------------------------------------------------------------
__in_subnet(){
    # Determine whether IP address is in the specified subnet.
    #
    # Args:
    #   sub: Subnet, in CIDR notation.
    #   ip: IP address to check.
    #
    # Returns:
    #   1|0
    #
    local ip ip_a mask netmask sub sub_ip rval start end

    # Define bitmask.
    local readonly  BITMASK=0xFFFFFFFF



    # Read arguments.
    IFS=/ read sub mask <<< "${1}"
    IFS=. read -a sub_ip <<< "${sub}"
    IFS=. read -a ip_a <<< "${2}"

    # Calculate netmask.
    netmask=$(($BITMASK<<$((32-$mask)) & $BITMASK))

    # Determine address range.
    start=0
    for o in "${sub_ip[@]}"
    do
        start=$(($start<<8 | $o))
    done

    start=$(($start & $netmask))
    end=$(($start | ~$netmask & $BITMASK))

    # Convert IP address to 32-bit number.
    ip=0
    for o in "${ip_a[@]}"
    do
        ip=$(($ip<<8 | $o))
    done

    # Determine if IP in range.
    (( $ip >= $start )) && (( $ip <= $end )) && rval=1 || rval=0

#    if [ $_ECHO_DEBUG ]; then
#        printf "ip=0x%08X; start=0x%08X; end=0x%08X; in_subnet=%u\n" $ip $start $end $rval 1>&2

    echo "${rval}"
}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  extract_primary_ip
#   DESCRIPTION:  get the primary ip from server
#----------------------------------------------------------------------------------------------------------------------
extract_primary_ip(){
    _PRIMARY_IP=$(ip addr show 2>/dev/null | grep -oP "(?<=inet ).*(?=/)")
    # echodebug $?
    if [ "$_SALT_ID_SUBNET" = "null" ]; then
        return
    fi
    if [ "$_PRIMARY_IP" = "null" ]; then
        echoerror "Can not found server's ip"
        exit 1
    fi
    for subnet in $_SALT_ID_SUBNET
    do
        if [[ $subnet =~ ^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([1-9]|1[0-9]|2[0-9]|3[0-2])$ ]]; then
            for IP in $_PRIMARY_IP
            do
                (( $( __in_subnet $subnet $IP) )) &&
                    echoinfo "${IP} is in ${subnet}"  && _SALT_MINION_ID=$IP && return
            done
        else
            echoerror "$subnet is not correct format! Please config SALT_ID_SUBNET correctly!"
            exit 1

        fi
    done

}



#----------------------------------------------------------------------------------------------------------------------
#  Handle server_id and salt_master_address arguments
#
#----------------------------------------------------------------------------------------------------------------------
_SALT_MINION_ID=${_SALT_MINION_ID:-null}
if [ $_SALT_MINION_ID = null ] && [ "$_SALT_ID_SUBNET" != "null" ]; then
    echoinfo "Get server_id from server's ip"
    extract_primary_ip
fi
if [ -f $_SALT_ETC_DIR/minion.d/id.conf ] && [ $_SALT_MINION_ID = null ]; then
    _SALT_MINION_ID=$(cat $_SALT_ETC_DIR/minion.d/id.conf | awk -F : '{print $2}' | tr -d [:blank:])
fi

_SALT_MASTER_ADDRESS=${_SALT_MASTER_ADDRESS:-null}
if [ -f $_SALT_ETC_DIR/minion.d/master.conf ] && [ $_SALT_MASTER_ADDRESS = null ]; then
   _SALT_MASTER_ADDRESS=$(cat $_SALT_ETC_DIR/minion.d/master.conf | awk -F : '{print $2}' | tr -d [:blank:])
fi


# Defaults for install arguments
FILENAME="salt-$__ScriptVersion.linux-x86_64.zip"

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#         NAME:  __usage
#  DESCRIPTION:  Display usage information.
#----------------------------------------------------------------------------------------------------------------------
__usage() {
  cat << EOT
  Usage :  ${__ScriptName} [options]
  Enviroment Variable:
    -  SALT_ID_SUBNET="10.10.0.0/24 192.168.26.1/18"
    - _SALT_MINION_ID="anm_window_10.10.0.104"
    - _SALT_MASTER_ADDRESS="10.10.0.42"
  Examples:
    - /bin/bash ${__ScriptName}
    - /bin/bash ${__ScriptName} -i anm_window_10.10.0.123 -A 10.10.0.42
    - /bin/bash ${__ScriptName} -i anm_window_10.10.0.123 -A 10.10.0.42 -f
    - /bin/bash ${__ScriptName} -i anm_window_10.10.0.123 -A 10.10.0.42 -f -b
    - SALT_ID_SUBNET="10.10.0.0/24 192.168.26.1/18" /bin/bash ${__ScriptName} -i anm_window_10.10.0.123 -A 10.10.0.42 -f
  Options:
    -h  Display this message
    -v  Display script version
    -n  No colours
    -D  Show debug output
    -A  Pass the salt-master DNS name or IP. This will be stored under
        \${_SALT_ETC_DIR}/minion.d/master.conf
    -i  Pass the salt-minion id. This will be stored under
        \${_SALT_ETC_DIR}/id.conf
    -b  No install filebeat for server.  (Default: yes)
    -f  Force install remove all file old installed
    -s  Sleep time used when waiting for daemons to start, restart and when
        checking for the services running. Default: ${__DEFAULT_SLEEP}

EOT
}   # ----------  end of function __usage  ----------


#Argument have : after is use OPTARGS example: i, A
#OPTIND is index of next argument
#Example: se-install.sh -Dfn -A 10.10.0.42 -i anm_window_10.10.0.42
#OPTIND of D:1 (next optin is f in 1) f: 1 (next option is n in 1) n:2 (next option is A in 2) A:3 (Next argument is 10.10.0.42 in 3)
#  i:5 (next option is anm_window_10.10.0.42 in 5)
while getopts ':hvnDbfA:i:c' opt
do

  case "${opt}" in

    h )  __usage; exit 0                                ;;
    v )  echo "$0 -- Version $__ScriptVersion"; exit 0  ;;
    n )  _COLORS=0; __detect_color_support              ;;
    D )  _ECHO_DEBUG=$BS_TRUE                           ;;
    A )  _SALT_MASTER_ADDRESS=$OPTARG                   ;;
    i )  _SALT_MINION_ID=$OPTARG                        ;;
    c )  _VALIDATE_SERVER_ID=$BS_FALSE                  ;;
    b )  _INSTALL_FILEBEAT=$BS_FALSE                    ;;
    f )  _FORCE_INSTALL=$BS_TRUE                        ;;
    \?)  echo
         echoerror "Option does not exist : $OPTARG"
         __usage
         exit 1
         ;;
  esac
done
shift $((OPTIND-1))


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#         NAME:  __whoami
#  DESCRIPTION:  Check the user permissions
#----------------------------------------------------------------------------------------------------------------------
__whoami(){
    # whoami alternative for SunOS
    if [ -f /usr/xpg4/bin/id ]; then
        whoami='/usr/xpg4/bin/id -un'
    else
        whoami='whoami'
    fi

    # Root permissions are required to run this script
    if [ "$($whoami)" != "root" ]; then
        echoerror "Salt requires root privileges to install. Please re-run this script as root."
        exit 1
    fi
}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#         NAME:  __get_caller
#  DESCRIPTION:  Check the user permissions
#----------------------------------------------------------------------------------------------------------------------
# Let's discover how we're being called
# shellcheck disable=SC2009
__get_caller(){
    CALLER=$(ps -a -o pid,args | grep $$ | grep -v grep | tr -s ' ' | cut -d ' ' -f 3)
    if [ "${CALLER}x" = "${0}x" ]; then
        CALLER="shell pipe"
    fi
}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __gather_hardware_info
#   DESCRIPTION:  Discover hardware information
#----------------------------------------------------------------------------------------------------------------------
__gather_hardware_info() {
    if [ -f /proc/cpuinfo ]; then
        CPU_VENDOR_ID=$(awk '/vendor_id|Processor/ {sub(/-.*$/,"",$3); print $3; exit}' /proc/cpuinfo )
    elif [ -f /usr/bin/kstat ]; then
        # SmartOS.
        # Solaris!?
        # This has only been tested for a GenuineIntel CPU
        CPU_VENDOR_ID=$(/usr/bin/kstat -p cpu_info:0:cpu_info0:vendor_id | awk '{print $2}')
    else
        CPU_VENDOR_ID=$( sysctl -n hw.model )
    fi
    # shellcheck disable=SC2034
    CPU_VENDOR_ID_L=$( echo "$CPU_VENDOR_ID" | tr '[:upper:]' '[:lower:]' )
    CPU_ARCH=$(uname -m 2>/dev/null || uname -p 2>/dev/null || echo "unknown")
    CPU_ARCH_L=$( echo "$CPU_ARCH" | tr '[:upper:]' '[:lower:]' )
}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __gather_os_info
#   DESCRIPTION:  Discover operating system information
#----------------------------------------------------------------------------------------------------------------------
__gather_os_info() {
    OS_NAME=$(uname -s 2>/dev/null)
    OS_NAME_L=$( echo "$OS_NAME" | tr '[:upper:]' '[:lower:]' )
    OS_VERSION=$(uname -r)
    # shellcheck disable=SC2034
    OS_VERSION_L=$( echo "$OS_VERSION" | tr '[:upper:]' '[:lower:]' )
}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __parse_version_string
#   DESCRIPTION:  Parse version strings ignoring the revision.
#                 MAJOR.MINOR.REVISION becomes MAJOR.MINOR
#----------------------------------------------------------------------------------------------------------------------
__parse_version_string() {
    VERSION_STRING="$1"
    PARSED_VERSION=$(
        echo "$VERSION_STRING" |
        sed -e 's/^/#/' \
            -e 's/^#[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\)\(\.[0-9][0-9]*\).*$/\1/' \
            -e 's/^#[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\).*$/\1/' \
            -e 's/^#[^0-9]*\([0-9][0-9]*\).*$/\1/' \
            -e 's/^#.*$//'
    )
    echo "$PARSED_VERSION"
}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __sort_release_files
#   DESCRIPTION:  Custom sort function. Alphabetical or numerical sort is not
#                 enough.
#----------------------------------------------------------------------------------------------------------------------
__sort_release_files() {
    KNOWN_RELEASE_FILES=$(echo "(arch|alpine|centos|debian|ubuntu|fedora|redhat|suse|\
        mandrake|mandriva|gentoo|slackware|turbolinux|unitedlinux|void|lsb|system|\
        oracle|os)(-|_)(release|version)" | sed -r 's:[[:space:]]::g')
    primary_release_files=""
    secondary_release_files=""
    # Sort know VS un-known files first
    for release_file in $(echo "${@}" | sed -r 's:[[:space:]]:\n:g' | sort -f | uniq); do
        match=$(echo "$release_file" | grep -E -i "${KNOWN_RELEASE_FILES}")
        if [ "${match}" != "" ]; then
            primary_release_files="${primary_release_files} ${release_file}"
        else
            secondary_release_files="${secondary_release_files} ${release_file}"
        fi
    done

    # Now let's sort by know files importance, max important goes last in the max_prio list
    max_prio="redhat-release centos-release oracle-release fedora-release"
    for entry in $max_prio; do
        if [ "$(echo "${primary_release_files}" | grep "$entry")" != "" ]; then
            primary_release_files=$(echo "${primary_release_files}" | sed -e "s:\\(.*\\)\\($entry\\)\\(.*\\):\\2 \\1 \\3:g")
        fi
    done
    # Now, least important goes last in the min_prio list
    min_prio="lsb-release"
    for entry in $min_prio; do
        if [ "$(echo "${primary_release_files}" | grep "$entry")" != "" ]; then
            primary_release_files=$(echo "${primary_release_files}" | sed -e "s:\\(.*\\)\\($entry\\)\\(.*\\):\\1 \\3 \\2:g")
        fi
    done

    # Echo the results collapsing multiple white-space into a single white-space
    echo "${primary_release_files} ${secondary_release_files}" | sed -r 's:[[:space:]]+:\n:g'
}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __derive_debian_numeric_version
#   DESCRIPTION:  Derive the numeric version from a Debian version string.
#----------------------------------------------------------------------------------------------------------------------
__derive_debian_numeric_version() {
    NUMERIC_VERSION=""
    INPUT_VERSION="$1"
    if echo "$INPUT_VERSION" | grep -q '^[0-9]'; then
        NUMERIC_VERSION="$INPUT_VERSION"
    elif [ -z "$INPUT_VERSION" ] && [ -f "/etc/debian_version" ]; then
        INPUT_VERSION="$(cat /etc/debian_version)"
    fi
    if [ -z "$NUMERIC_VERSION" ]; then
        if [ "$INPUT_VERSION" = "wheezy/sid" ]; then
            # I've found an EC2 wheezy image which did not tell its version
            NUMERIC_VERSION=$(__parse_version_string "7.0")
        elif [ "$INPUT_VERSION" = "jessie/sid" ]; then
            NUMERIC_VERSION=$(__parse_version_string "8.0")
        elif [ "$INPUT_VERSION" = "stretch/sid" ]; then
            NUMERIC_VERSION=$(__parse_version_string "9.0")
        elif [ "$INPUT_VERSION" = "buster/sid" ]; then
            NUMERIC_VERSION=$(__parse_version_string "10.0")
        else
            echowarn "Unable to parse the Debian Version (codename: '$INPUT_VERSION')"
        fi
    fi
    echo "$NUMERIC_VERSION"
}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __check_end_of_life_versions
#   DESCRIPTION:  Check for end of life distribution versions
#----------------------------------------------------------------------------------------------------------------------
__check_end_of_life_versions() {
    echoinfo "Check end of life versions"
    case "${DISTRO_NAME_L}" in
        debian)
            # Debian versions below 7 are not supported
            if [ "$DISTRO_MAJOR_VERSION" -lt 7 ]; then
                echoerror "End of life distributions are not supported."
                echoerror "Please consider upgrading to the next stable. See:"
                echoerror "    https://wiki.debian.org/DebianReleases"
                exit 1
            fi
            ;;

        ubuntu)
            # Ubuntu versions not supported
            #
            #  < 14.04
            #  = 14.10
            #  = 15.04, 15.10
            #  = 16.10
            #  = 17.04, 17.10
            if [ "$DISTRO_MAJOR_VERSION" -lt 14 ] || \
                [ "$DISTRO_MAJOR_VERSION" -eq 15 ] || \
                [ "$DISTRO_MAJOR_VERSION" -eq 17 ] || \
                { [ "$DISTRO_MAJOR_VERSION" -eq 16 ] && [ "$DISTRO_MINOR_VERSION" -eq 10 ]; }; then
                echoerror "End of life distributions are not supported."
                echoerror "Please consider upgrading to the next stable. See:"
                echoerror "    https://wiki.ubuntu.com/Releases"
                exit 1
            fi
            ;;

        opensuse)
            # openSUSE versions not supported
            #
            #  <= 13.X
            #  <= 42.2
            if [ "$DISTRO_MAJOR_VERSION" -lt 15 ] || \
                { [ "$DISTRO_MAJOR_VERSION" -eq 42 ] && [ "$DISTRO_MINOR_VERSION" -le 2 ]; }; then
                echoerror "End of life distributions are not supported."
                echoerror "Please consider upgrading to the next stable. See:"
                echoerror "    http://en.opensuse.org/Lifetime"
                exit 1
            fi
            ;;

        suse)
            # SuSE versions not supported
            #
            # < 11 SP4
            # < 12 SP2
            SUSE_PATCHLEVEL=$(awk '/PATCHLEVEL/ {print $3}' /etc/SuSE-release )
            if [ "${SUSE_PATCHLEVEL}" = "" ]; then
                SUSE_PATCHLEVEL="00"
            fi
            if [ "$DISTRO_MAJOR_VERSION" -lt 11 ] || \
                { [ "$DISTRO_MAJOR_VERSION" -eq 11 ] && [ "$SUSE_PATCHLEVEL" -lt 04 ]; } || \
                { [ "$DISTRO_MAJOR_VERSION" -eq 12 ] && [ "$SUSE_PATCHLEVEL" -lt 02 ]; }; then
                echoerror "Versions lower than SuSE 11 SP4 or 12 SP2 are not supported."
                echoerror "Please consider upgrading to the next stable"
                echoerror "    https://www.suse.com/lifecycle/"
                exit 1
            fi
            ;;

        fedora)
            # Fedora lower than 27 are no longer supported
            if [ "$DISTRO_MAJOR_VERSION" -lt 27 ]; then
                echoerror "End of life distributions are not supported."
                echoerror "Please consider upgrading to the next stable. See:"
                echoerror "    https://fedoraproject.org/wiki/Releases"
                exit 1
            fi
            ;;

        centos)
            # CentOS versions lower than 6 are no longer supported
            if [ "$DISTRO_MAJOR_VERSION" -lt 6 ]; then
                echoerror "End of life distributions are not supported."
                echoerror "Please consider upgrading to the next stable. See:"
                echoerror "    http://wiki.centos.org/Download"
                exit 1
            fi
            ;;

        red_hat*linux)
            # Red Hat (Enterprise) Linux versions lower than 6 are no longer supported
            if [ "$DISTRO_MAJOR_VERSION" -lt 6 ]; then
                echoerror "End of life distributions are not supported."
                echoerror "Please consider upgrading to the next stable. See:"
                echoerror "    https://access.redhat.com/support/policy/updates/errata/"
                exit 1
            fi
            ;;

        oracle*linux)
            # Oracle Linux versions lower than 6 are no longer supported
            if [ "$DISTRO_MAJOR_VERSION" -lt 6 ]; then
                echoerror "End of life distributions are not supported."
                echoerror "Please consider upgrading to the next stable. See:"
                echoerror "    http://www.oracle.com/us/support/library/elsp-lifetime-069338.pdf"
                exit 1
            fi
            ;;

        scientific*linux)
            # Scientific Linux versions lower than 6 are no longer supported
            if [ "$DISTRO_MAJOR_VERSION" -lt 6 ]; then
                echoerror "End of life distributions are not supported."
                echoerror "Please consider upgrading to the next stable. See:"
                echoerror "    https://www.scientificlinux.org/downloads/sl-versions/"
                exit 1
            fi
            ;;

        cloud*linux)
            # Cloud Linux versions lower than 6 are no longer supported
            if [ "$DISTRO_MAJOR_VERSION" -lt 6 ]; then
                echoerror "End of life distributions are not supported."
                echoerror "Please consider upgrading to the next stable. See:"
                echoerror "    https://docs.cloudlinux.com/index.html?cloudlinux_life-cycle.html"
                exit 1
            fi
            ;;

        amazon*linux*ami)
            # Amazon Linux versions lower than 2012.0X no longer supported
            # Except for Amazon Linux 2, which reset the major version counter
            if [ "$DISTRO_MAJOR_VERSION" -lt 2012 ] && [ "$DISTRO_MAJOR_VERSION" -gt 10 ]; then
                echoerror "End of life distributions are not supported."
                echoerror "Please consider upgrading to the next stable. See:"
                echoerror "    https://aws.amazon.com/amazon-linux-ami/"
                exit 1
            fi
            ;;

        freebsd)
            # FreeBSD versions lower than 9.1 are not supported.
            if { [ "$DISTRO_MAJOR_VERSION" -eq 9 ] && [ "$DISTRO_MINOR_VERSION" -lt 01 ]; } || \
                [ "$DISTRO_MAJOR_VERSION" -lt 9 ]; then
                echoerror "Versions lower than FreeBSD 9.1 are not supported."
                exit 1
            fi
            ;;

        *)
            ;;
    esac
    echodebug "Finish check end of life versions"
}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __gather_linux_system_info
#   DESCRIPTION:  Discover Linux system information
#----------------------------------------------------------------------------------------------------------------------
__gather_linux_system_info() {
    DISTRO_NAME=""
    DISTRO_VERSION=""

    # Let's test if the lsb_release binary is available
    rv=$(lsb_release >/dev/null 2>&1)

    # shellcheck disable=SC2181
    if [ $? -eq 0 ]; then
        DISTRO_NAME=$(lsb_release -si)
        if [ "${DISTRO_NAME}" = "Scientific" ]; then
            DISTRO_NAME="Scientific Linux"
        elif [ "$(echo "$DISTRO_NAME" | grep ^CloudLinux)" != "" ]; then
            DISTRO_NAME="Cloud Linux"
        elif [ "$(echo "$DISTRO_NAME" | grep ^RedHat)" != "" ]; then
            # Let's convert 'CamelCased' to 'Camel Cased'
            n=$(__camelcase_split "$DISTRO_NAME")
            # Skip setting DISTRO_NAME this time, splitting CamelCase has failed.
            # See https://github.com/saltstack/salt-bootstrap/issues/918
            [ "$n" = "$DISTRO_NAME" ] && DISTRO_NAME="" || DISTRO_NAME="$n"
        elif [ "${DISTRO_NAME}" = "openSUSE project" ]; then
            # lsb_release -si returns "openSUSE project" on openSUSE 12.3
            # lsb_release -si returns "openSUSE" on openSUSE 15.n
            DISTRO_NAME="opensuse"
        elif [ "${DISTRO_NAME}" = "SUSE LINUX" ]; then
            if [ "$(lsb_release -sd | grep -i opensuse)" != "" ]; then
                # openSUSE 12.2 reports SUSE LINUX on lsb_release -si
                DISTRO_NAME="opensuse"
            else
                # lsb_release -si returns "SUSE LINUX" on SLES 11 SP3
                DISTRO_NAME="suse"
            fi
        elif [ "${DISTRO_NAME}" = "EnterpriseEnterpriseServer" ]; then
            # This the Oracle Linux Enterprise ID before ORACLE LINUX 5 UPDATE 3
            DISTRO_NAME="Oracle Linux"
        elif [ "${DISTRO_NAME}" = "OracleServer" ]; then
            # This the Oracle Linux Server 6.5
            DISTRO_NAME="Oracle Linux"
        elif [ "${DISTRO_NAME}" = "AmazonAMI" ] || [ "${DISTRO_NAME}" = "Amazon" ]; then
            DISTRO_NAME="Amazon Linux AMI"
        elif [ "${DISTRO_NAME}" = "ManjaroLinux" ]; then
            DISTRO_NAME="Arch Linux"
        elif [ "${DISTRO_NAME}" = "Arch" ]; then
            DISTRO_NAME="Arch Linux"
            return
        fi
        rv=$(lsb_release -sr)
        [ "${rv}" != "" ] && DISTRO_VERSION=$(__parse_version_string "$rv")
    elif [ -f /etc/lsb-release ]; then
        # We don't have the lsb_release binary, though, we do have the file it parses
        DISTRO_NAME=$(grep DISTRIB_ID /etc/lsb-release | sed -e 's/.*=//')
        rv=$(grep DISTRIB_RELEASE /etc/lsb-release | sed -e 's/.*=//')
        [ "${rv}" != "" ] && DISTRO_VERSION=$(__parse_version_string "$rv")
    fi

    if [ "$DISTRO_NAME" != "" ] && [ "$DISTRO_VERSION" != "" ]; then
        # We already have the distribution name and version
        return
    fi
    # shellcheck disable=SC2035,SC2086
    for rsource in $(__sort_release_files "$(
            cd /etc && /bin/ls *[_-]release *[_-]version 2>/dev/null | env -i sort | \
            sed -e '/^redhat-release$/d' -e '/^lsb-release$/d'; \
            echo redhat-release lsb-release
            )"); do

        [ ! -f "/etc/${rsource}" ] && continue      # Does not exist

        n=$(echo "${rsource}" | sed -e 's/[_-]release$//' -e 's/[_-]version$//')
        shortname=$(echo "${n}" | tr '[:upper:]' '[:lower:]')
        if [ "$shortname" = "debian" ]; then
            rv=$(__derive_debian_numeric_version "$(cat /etc/${rsource})")
        else
            rv=$( (grep VERSION "/etc/${rsource}"; cat "/etc/${rsource}") | grep '[0-9]' | sed -e 'q' )
        fi
        [ "${rv}" = "" ] && [ "$shortname" != "arch" ] && continue  # There's no version information. Continue to next rsource
        v=$(__parse_version_string "$rv")
        case $shortname in
            redhat             )
                if [ "$(grep -E 'CentOS' /etc/${rsource})" != "" ]; then
                    n="CentOS"
                elif [ "$(grep -E 'Scientific' /etc/${rsource})" != "" ]; then
                    n="Scientific Linux"
                elif [ "$(grep -E 'Red Hat Enterprise Linux' /etc/${rsource})" != "" ]; then
                    n="<R>ed <H>at <E>nterprise <L>inux"
                else
                    n="<R>ed <H>at <L>inux"
                fi
                ;;
            arch               ) n="Arch Linux"     ;;
            alpine             ) n="Alpine Linux"   ;;
            centos             ) n="CentOS"         ;;
            debian             ) n="Debian"         ;;
            ubuntu             ) n="Ubuntu"         ;;
            fedora             ) n="Fedora"         ;;
            suse|opensuse      ) n="SUSE"           ;;
            mandrake*|mandriva ) n="Mandriva"       ;;
            gentoo             ) n="Gentoo"         ;;
            slackware          ) n="Slackware"      ;;
            turbolinux         ) n="TurboLinux"     ;;
            unitedlinux        ) n="UnitedLinux"    ;;
            void               ) n="VoidLinux"      ;;
            oracle             ) n="Oracle Linux"   ;;
            system             )
                while read -r line; do
                    [ "${n}x" != "systemx" ] && break
                    case "$line" in
                        *Amazon*Linux*AMI*)
                            n="Amazon Linux AMI"
                            break
                    esac
                done < "/etc/${rsource}"
                ;;
            os                 )
                nn="$(__unquote_string "$(grep '^ID=' /etc/os-release | sed -e 's/^ID=\(.*\)$/\1/g')")"
                rv="$(__unquote_string "$(grep '^VERSION_ID=' /etc/os-release | sed -e 's/^VERSION_ID=\(.*\)$/\1/g')")"
                [ "${rv}" != "" ] && v=$(__parse_version_string "$rv") || v=""
                case $(echo "${nn}" | tr '[:upper:]' '[:lower:]') in
                    alpine      )
                        n="Alpine Linux"
                        v="${rv}"
                        ;;
                    amzn        )
                        # Amazon AMI's after 2014.09 match here
                        n="Amazon Linux AMI"
                        ;;
                    arch        )
                        n="Arch Linux"
                        v=""  # Arch Linux does not provide a version.
                        ;;
                    cloudlinux  )
                        n="Cloud Linux"
                        ;;
                    debian      )
                        n="Debian"
                        v=$(__derive_debian_numeric_version "$v")
                        ;;
                    sles  )
                        n="SUSE"
                        v="${rv}"
                        ;;
                    opensuse-leap  )
                        n="opensuse"
                        v="${rv}"
                        ;;
                    *           )
                        n=${nn}
                        ;;
                esac
                ;;
            *                  ) n="${n}"           ;
        esac
        DISTRO_NAME=$n
        DISTRO_VERSION=$v
        break
    done
}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __gather_system_info
#   DESCRIPTION:  Discover which system and distribution we are running.
#----------------------------------------------------------------------------------------------------------------------
__gather_system_info() {
    case ${OS_NAME_L} in
        linux )
            __gather_linux_system_info
            ;;
        sunos )
            __gather_sunos_system_info
            ;;
        openbsd|freebsd|netbsd )
            __gather_bsd_system_info
            ;;
        darwin )
            __gather_osx_system_info
            ;;
        * )
        echoerror "${OS_NAME} not supported.";
        exit 1
        ;;
    esac

}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __function_defined
#   DESCRIPTION:  Checks if a function is defined within this scripts scope
#    PARAMETERS:  function name
#       RETURNS:  0 or 1 as in defined or not defined
#----------------------------------------------------------------------------------------------------------------------
__function_defined() {
    FUNC_NAME=$1
    if [ "$(command -v "$FUNC_NAME")" != "" ]; then
        echoinfo "Found function $FUNC_NAME"
        return 0
    fi
    echodebug "$FUNC_NAME not found...."
    return 1
}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __strip_duplicates
#   DESCRIPTION:  Strip duplicate strings
#----------------------------------------------------------------------------------------------------------------------
__strip_duplicates() {
    echo "$*" | tr -s '[:space:]' '\n' | awk '!x[$0]++'
}

#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __get_install_function
#   DESCRIPTION:  Get all install function corresponding distro
#----------------------------------------------------------------------------------------------------------------------
__get_install_function(){
    # Let's get the install function
    INSTALL_FUNC_NAMES="install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}"
    INSTALL_FUNC_NAMES="$INSTALL_FUNC_NAMES install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}${PREFIXED_DISTRO_MINOR_VERSION}"
    INSTALL_FUNC_NAMES="$INSTALL_FUNC_NAMES install_${DISTRO_NAME_L}"
    INSTALL_FUNC_NAMES="$INSTALL_FUNC_NAMES install_${OS_NAME_L}"

    echodebug "INSTALL_FUNC_NAMES=${INSTALL_FUNC_NAMES}"

    INSTALL_FUNC="null"
    for FUNC_NAME in $(__strip_duplicates "$INSTALL_FUNC_NAMES"); do
        if __function_defined "$FUNC_NAME"; then
            INSTALL_FUNC="$FUNC_NAME"
            break
        fi
    done
    echodebug "INSTALL_FUNC=${INSTALL_FUNC}"
}
#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __get_stop_deamons_function
#   DESCRIPTION:  Get all install function corresponding distro
#----------------------------------------------------------------------------------------------------------------------
__get_stop_deamons_function(){
    #Let's get the stop deamons function
    STOP_DAEMONS_FUNC_NAMES="install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}_stop_daemons"
    STOP_DAEMONS_FUNC_NAMES="$STOP_DAEMONS_FUNC_NAMES install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}${PREFIXED_DISTRO_MINOR_VERSION}_stop_daemons"
    STOP_DAEMONS_FUNC_NAMES="$STOP_DAEMONS_FUNC_NAMES install_${DISTRO_NAME_L}_stop_daemons"
    STOP_DAEMONS_FUNC_NAMES="$STOP_DAEMONS_FUNC_NAMES install_${OS_NAME_L}_stop_daemons"
    echodebug "STOP_DAEMONS_FUNC_NAME=${STOP_DAEMONS_FUNC_NAMES}"
    STOP_DAEMONS_FUNC="null"
    for FUNC_NAME in $(__strip_duplicates "$STOP_DAEMONS_FUNC_NAMES"); do
        if __function_defined "$FUNC_NAME"; then
            STOP_DAEMONS_FUNC="$FUNC_NAME"
            break
        fi
    done
    echodebug "STOP_DAEMONS_FUNC=${STOP_DAEMONS_FUNC}"

}
#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __get_post_install_function
#   DESCRIPTION:  Get all post install function corresponding distro
#----------------------------------------------------------------------------------------------------------------------
__get_post_install_function(){
    # Let's get the post install function
    POST_FUNC_NAMES="install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}_post"
    POST_FUNC_NAMES="$POST_FUNC_NAMES install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}${PREFIXED_DISTRO_MINOR_VERSION}_post"
    POST_FUNC_NAMES="$POST_FUNC_NAMES install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}_post"
    POST_FUNC_NAMES="$POST_FUNC_NAMES install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}${PREFIXED_DISTRO_MINOR_VERSION}_post"
    POST_FUNC_NAMES="$POST_FUNC_NAMES install_${DISTRO_NAME_L}_post"
    POST_FUNC_NAMES="$POST_FUNC_NAMES install_${DISTRO_NAME_L}_post"
    POST_FUNC_NAMES="$POST_FUNC_NAMES install_${OS_NAME_L}_post"

    POST_INSTALL_FUNC="null"
    for FUNC_NAME in $(__strip_duplicates "$POST_FUNC_NAMES"); do
        if __function_defined "$FUNC_NAME"; then
            POST_INSTALL_FUNC="$FUNC_NAME"
            break
        fi
    done
    echodebug "POST_INSTALL_FUNC=${POST_INSTALL_FUNC}"

}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __get_install_other_agent_function
#   DESCRIPTION:  Get all install other agent function
#----------------------------------------------------------------------------------------------------------------------
__get_install_other_agent_function(){
    # Let's get the other agent install function
    INSTALL_OTHER_AGENTS_FUNC_NAMES="install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}__agents"
    INSTALL_OTHER_AGENTS_FUNC_NAMES="$INSTALL_OTHER_AGENTS_FUNC_NAMES install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}${PREFIXED_DISTRO_MINOR_VERSION}_other_agents"
    INSTALL_OTHER_AGENTS_FUNC_NAMES="$INSTALL_OTHER_AGENTS_FUNC_NAMES install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}_post"
    INSTALL_OTHER_AGENTS_FUNC_NAMES="$INSTALL_OTHER_AGENTS_FUNC_NAMES install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}${PREFIXED_DISTRO_MINOR_VERSION}_other_agents"
    INSTALL_OTHER_AGENTS_FUNC_NAMES="$INSTALL_OTHER_AGENTS_FUNC_NAMES install_${DISTRO_NAME_L}_other_agents"
    INSTALL_OTHER_AGENTS_FUNC_NAMES="$INSTALL_OTHER_AGENTS_FUNC_NAMES install_${DISTRO_NAME_L}_other_agents"
    INSTALL_OTHER_AGENTS_FUNC_NAMES="$INSTALL_OTHER_AGENTS_FUNC_NAMES install_${OS_NAME_L}_other_agents"

    INSTALL_OTHER_AGENTS_FUNC="null"
    for FUNC_NAME in $(__strip_duplicates "$INSTALL_OTHER_AGENTS_FUNC_NAMES"); do
        if __function_defined "$FUNC_NAME"; then
            INSTALL_OTHER_AGENTS_FUNC="$FUNC_NAME"
            break
        fi
    done
    echodebug "INSTALL_OTHER_AGENTS_FUNC=${INSTALL_OTHER_AGENTS_FUNC}"

}
#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#          NAME:  __get_install_resstart_daemons_function
#   DESCRIPTION:  Get all install restart daemons function
#----------------------------------------------------------------------------------------------------------------------
__get_install_restart_daemons_function(){
    # Let's get the start daemons install function
    STARTDAEMONS_FUNC_NAMES="install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}_restart_daemons"
    STARTDAEMONS_FUNC_NAMES="$STARTDAEMONS_FUNC_NAMES install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}${PREFIXED_DISTRO_MINOR_VERSION}_restart_daemons"
    STARTDAEMONS_FUNC_NAMES="$STARTDAEMONS_FUNC_NAMES install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}_restart_daemons"
    STARTDAEMONS_FUNC_NAMES="$STARTDAEMONS_FUNC_NAMES install_${DISTRO_NAME_L}${PREFIXED_DISTRO_MAJOR_VERSION}${PREFIXED_DISTRO_MINOR_VERSION}_restart_daemons"
    STARTDAEMONS_FUNC_NAMES="$STARTDAEMONS_FUNC_NAMES install_${DISTRO_NAME_L}_restart_daemons"
    STARTDAEMONS_FUNC_NAMES="$STARTDAEMONS_FUNC_NAMES install_${OS_NAME_L}_restart_daemons"
    STARTDAEMONS_INSTALL_FUNC="null"
    for FUNC_NAME in $(__strip_duplicates "$STARTDAEMONS_FUNC_NAMES"); do
        if __function_defined "$FUNC_NAME"; then
            STARTDAEMONS_INSTALL_FUNC="$FUNC_NAME"
            break
        fi
    done
    echodebug "STARTDAEMONS_INSTALL_FUNC=${STARTDAEMONS_INSTALL_FUNC}"

}
#--- FUNCTION  --------------------------------------------------------------------------------------------------
#          NAME:  __simplify_distro_and_prefix_version
#   DESCRIPTION:  Simplify distro name naming on functions
#----------------------------------------------------------------------------------------------------------------------
__simplify_distro_and_prefix_version(){
    # Simplify distro name naming on functions
    DISTRO_NAME_L=$(echo "$DISTRO_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-zA-Z0-9_ ]//g' | sed -re 's/([[:space:]])+/_/g')

    # Simplify version naming on functions
    if [ "$DISTRO_VERSION" = "" ]; then
        DISTRO_MAJOR_VERSION="a"
        DISTRO_MINOR_VERSION="b"
        PREFIXED_DISTRO_MAJOR_VERSION=""
        PREFIXED_DISTRO_MINOR_VERSION=""
    else
        DISTRO_MAJOR_VERSION=$(echo "$DISTRO_VERSION" | sed 's/^\([0-9]*\).*/\1/g')
        DISTRO_MINOR_VERSION=$(echo "$DISTRO_VERSION" | sed 's/^\([0-9]*\).\([0-9]*\).*/\2/g')
        PREFIXED_DISTRO_MAJOR_VERSION="_${DISTRO_MAJOR_VERSION}"
        if [ "${PREFIXED_DISTRO_MAJOR_VERSION}" = "_" ]; then
            PREFIXED_DISTRO_MAJOR_VERSION=""
        fi
        PREFIXED_DISTRO_MINOR_VERSION="_${DISTRO_MINOR_VERSION}"
        if [ "${PREFIXED_DISTRO_MINOR_VERSION}" = "_" ]; then
            PREFIXED_DISTRO_MINOR_VERSION=""
        fi
    fi
}

#--- FUNCTION  --------------------------------------------------------------------------------------------------
#          NAME:  __check_package
#   DESCRIPTION:  Check  package name is installed or not
#    PARAMETERS:  package name
#        RETURN:  1 or 0 as in installed or not installed
#----------------------------------------------------------------------------------------------------------------------
__check_package(){
    PACKAGE_NAME=$1
    check_package=`which $PACKAGE_NAME  2>/dev/null | wc -l`
    if [ $check_package -eq $BS_FALSE ]; then
       echodebug "No package $PACKAGE_NAME."
       return 0
    fi
    echodebug "$PACKAGE_NAME is installed"
    return 1
}
#--- FUNCTION  --------------------------------------------------------------------------------------------------
#          NAME:  __check_dependence
#   DESCRIPTION:  Check  package name is installed or not
#----------------------------------------------------------------------------------------------------------------------
__check_dependence(){
    __check_package "wget"
    CHECK_WGET=$?
    __check_package "curl"
    CHECK_CURL=$?
    if [ $CHECK_CURL -eq $BS_TRUE ]; then
       _METHOD_TRANSFER="curl"
    elif [ $CHECK_WGET -eq $BS_TRUE ]; then
        _METHOD_TRANSFER="wget"
    else
        echoerror "wget and curl is not installed. please install wget or curl."
        exit 1
    fi

    __check_filebeat
    CHECK_FILEBEAT=$?
    if [ $CHECK_FILEBEAT -eq $BS_TRUE ]; then
        if [ $_FORCE_INSTALL -eq $BS_FALSE ]; then
            echowarn "Filebeat already installed. Please use option -f to uninstall filebeat and continue install salt-minion. Use option -b to install salt-minion without filebeat"
            __usage
            exit 1
        elif [ $_FORCE_INSTALL -eq $BS_TRUE ]; then
            echowarn "Filebeat already installed"
            echoinfo "Filebeat is uninstalling..."
            __uninstall_filebeat
        fi
    fi 
}

__check_filebeat(){
    if [ "${DISTRO_NAME}" = "Debian" ] || [ "${DISTRO_NAME}" = "Ubuntu" ]; then
        check_filebeat=`dpkg-query -l | grep filebeat | wc -l`
        if [ "$check_filebeat" != "0" ]; then
            return 1
        fi
    elif  [ "${DISTRO_NAME}" = "CentOS" ] || [ "${DISTRO_NAME}" = "Oracle Linux" ]; then
        check_filebeat=`rpm -qa | grep filebeat | wc -l`
        if [ "$check_filebeat" != "0" ]; then
            return 1
        fi
    fi
    return 0
}


#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#         NAME:  __uninstall_filebeat
#  DESCRIPTION:  Uninstall filebeat corresponding os
#----------------------------------------------------------------------------------------------------------------------
__uninstall_filebeat(){
    echoinfo "Uninstalling current version of Filebeat"
    if [ "${DISTRO_NAME}" = "Debian" ] || [ "${DISTRO_NAME}" = "Ubuntu" ]; then
        dpkg --purge filebeat >/dev/null 2>&1
    elif  [ "${DISTRO_NAME}" = "CentOS" ] || [ "${DISTRO_NAME}" = "Oracle Linux" ]; then
        yum remove -y filebeat >/dev/null 2>&1
    fi

    ps -ef | grep filebeat | grep -v grep | awk '{print $2}' | xargs kill -9 >/dev/null 2>&1
    echoinfo "Remove Filebeat install dir, config"
#    rm -rf $_FILEBEAT_INSTALL_DIR
#    rm -rf $_FILEBEAT_ETC_DIR
}



#---  FUNCTION  -------------------------------------------------------------------------------------------------------
#         NAME:  __fetch_url
#  DESCRIPTION:  Retrieves a URL and writes it to a given path
#----------------------------------------------------------------------------------------------------------------------
__fetch_url() {
    # shellcheck disable=SC2086
    curl $_CURL_ARGS -L -s -o "$1" "$2" >/dev/null 2>&1        ||
        wget $_WGET_ARGS -q -O "$1" "$2" >/dev/null 2>&1       ||
            fetch $_FETCH_ARGS -q -o "$1" "$2" >/dev/null 2>&1 ||  # FreeBSD
                fetch -q -o "$1" "$2" >/dev/null 2>&1          ||  # Pre FreeBSD 10
                    ftp -o "$1" "$2" >/dev/null 2>&1               # OpenBSD
}


#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  __validate_master_ip
#   DESCRIPTION: validate the master ip
#----------------------------------------------------------------------------------------------------------------------
__validate_master_ip(){
    echoinfo "Validate master ip"
    #check master ip is null or not
    if [ "$_SALT_MASTER_ADDRESS" = "null" ]; then
        echoerror "Master's ip is null! Please use -A option to config Master Ip!"
        __usage
        exit 1
    fi
    if [ $_METHOD_TRANSFER = "curl" ]; then
        #Using -f for show fail error code 22
        curl -sSf http://$_SALT_MASTER_ADDRESS/serverendpoint/se-install.sh --connect-timeout $_SLEEP > /dev/null 2>&1
        if [ $? != "0" ]; then
            echoerror "Can not connect to master ip! Please check connection to master ip port 80, 4505, 4506, 443, 6379"
            exit 1
        fi
    fi
    if [ $_METHOD_TRANSFER = "wget" ]; then
        wget -q http://$_SALT_MASTER_ADDRESS/serverendpoint/se-install.sh -T $_SLEEP --tries=1 > /dev/null 2>&1
        if [ $? -gt 0 ]; then
            echoerror "Can not connect to master ip! Please check connection to master ip port 80, 4505, 4506, 443, 6379"
            exit 1
        fi
    fi

}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  __validate_server_id
#   DESCRIPTION: validate the server id, check status server_id is rejected or accept or not exist
#----------------------------------------------------------------------------------------------------------------------
__validate_server_id(){
    echoinfo "Validate server id"
    #check server id is null or not
    if [ "$_SALT_MINION_ID" = "null" ]; then
        echoerror "Server id is null! Please use -i option to config minion server_id!"
        __usage
        exit 1
    fi
    if [ $_VALIDATE_SERVER_ID -eq $BS_TRUE ]; then
        CERT_STATUS=-null
        if [ $_METHOD_TRANSFER = "curl" ]; then
            CERT_STATUS=$(curl -sSf http://$_SALT_MASTER_ADDRESS/api/v2/cert_status?id=$_SALT_MINION_ID | grep -oP "(?<=status\"\:\s\").*(?=\")")
            if [ $? != "0" ]; then
                echoerror "Api error! Please check the seapi_v2  in server express."
                exit 1
            fi
        elif [ $_METHOD_TRANSFER = "wget" ]; then
            CERT_STATUS=$(wget -q -O- http://$_SALT_MASTER_ADDRESS/api/v2/cert_status?id=$_SALT_MINION_ID | grep -oP "(?<=status\"\:\s\").*(?=\")")
             if [ $? -gt 0 ]; then
                echoerror "Api error! Please check the seapi_v2  in server express."
                exit 1
            fi
        fi


        if [ $CERT_STATUS = "nok_not_existed" ]; then
            echoerror "Server id is not existed! Please create it in portal"
            exit 1
        elif [ $CERT_STATUS = "ok_is_used" ]; then
            echowarn "Server id is used!"
            if [ $_FORCE_INSTALL -eq $BS_FALSE ]; then
                echoerror "Server id is used! Please use -f option to force install"
                exit 1
            fi
        elif [ $CERT_STATUS = "nok_rejected" ]; then
            echoerror "Server id is rejected! Please renew it in portal"
            exit 1
        elif [ $CERT_STATUS = "nok_pending" ]; then
            echoerror "Server id is Pending! Please renew or accept it in portal"
            exit 1
        fi
    else
        echowarn "The validation cert status is off! Please check the server id  carefullly!"

    fi

}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  __is_se_installed
#   DESCRIPTION: check server endpoint is installed or not
#        RETURN: 1 or 0 as installed or not installed
#----------------------------------------------------------------------------------------------------------------------
__is_se_installed(){
    if [ -d "$_INSTALL_DIR" ] && [ -d "$_SALT_ETC_DIR" ]; then
        echowarn "Server Endpoint is installed"
        return 1
    fi
    echoinfo "Server Endpoint is not installed"
    return 0
}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  __uninstall
#   DESCRIPTION: Delete directory install_dir old file and etc_dir old file
#----------------------------------------------------------------------------------------------------------------------
__uninstall(){
    echoinfo "Running uninstall salt-minion"
    ps -ef | grep salt-minion | grep -v grep | awk '{print $2}' | xargs kill -9 >/dev/null 2>&1
    echoinfo "Remove install dir, config, pki dir"
    rm -rf $_INSTALL_DIR
    rm -rf $_SALT_ETC_DIR
    rm -rf $_VAR_CACHE_SALT

}

__download_file(){
    PATH_SAVE_FILE=$1
    FILE_NAME=$2
    #Check unzip and wget, curl installed
     __check_package "wget"
    CHECk_WGET=$?
    __check_package "curl"
    CHECK_CURL=$?
    if [ $CHECk_WGET -eq $BS_TRUE ]; then
        #Download file name without message (-q), save to PATH_SAVE_FILE (-P)
        echodebug "Download file $FILE_NAME to $PATH_SAVE_FILE complete"
        wget -q -O $PATH_SAVE_FILE $FILE_NAME
        if [ $? -gt 0 ]; then
            echoerror "Can not download $FILE_NAME to $PATH_SAVE_FILE! Please check the name file."
            exit 1
        fi
    elif [ $CHECK_CURL -eq $BS_TRUE ]; then
        #Download file name without message (-s) show error when they occurs, save to PATH_SAVE_FILE (-o)
         if [ $_ECHO_DEBUG -eq $BS_FALSE ]; then
            curl -sSf -o $PATH_SAVE_FILE $FILE_NAME > /dev/null 2>&1
            res=$?
         else
            curl -f -o $PATH_SAVE_FILE $FILE_NAME > /dev/null 2>&1
            res=$?
         fi
         if [ $res != "0" ]; then
            echoerror "Can not download $FILE_NAME to $PATH_SAVE_FILE! Please check the name file."
            exit 1
         fi
         echodebug "Download file $FILE_NAME to $PATH_SAVE_FILE complete"
    else
        echoerror "Can't get file $FILE_NAME"
        exit 1
    fi

}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_linux
#   DESCRIPTION:  The big function install for all distro linux.
#----------------------------------------------------------------------------------------------------------------------
install_linux(){
    __download_file $_INSTALL_DIR/$FILENAME http://"$_SALT_MASTER_ADDRESS"/serverendpoint/"$FILENAME"
    __check_package "unzip"
    CHECK_UNZIP=$?
    if [ "$CHECK_UNZIP" -eq $BS_TRUE ]; then
        unzip -q $FILENAME
    else
        echoerror "Unzip is not installed"
        exit 1
    fi

    #Create service salt-minion for centos
    echoinfo "Create service salt-minion for centos"
    #Download file services
    __download_file $_INSTALL_DIR/service_centos http://"$_SALT_MASTER_ADDRESS"/serverendpoint/service_centos
    echodebug "Format service_centos"
    sed -i "s+SALTMINION=/usr/local/sbin/salt-minion+SALTMINION=$_INSTALL_DIR/salt-minion+g" $_INSTALL_DIR/service_centos
    sed -i 's+MINION_ARGS=""+MINION_ARGS="-c'$_SALT_ETC_DIR'"+g' $_INSTALL_DIR/service_centos
    #chmod dir install (default /opt/se)
    mv $_INSTALL_DIR/service_centos /etc/init.d/salt-minion
    chmod 0755 /etc/init.d/salt-minion

    #Config auto start service



    #TODO create dir pki, config
    echoinfo "Create dir pki, config"
    mkdir -p ${_SALT_ETC_DIR}/minion.d
    mkdir -p ${_SALT_ETC_DIR}/pki/minion
    mkdir -p ${_SALT_ETC_DIR}/pki/master


    #Create file config id.conf master.conf os.conf api.conf
    echoinfo "create file config id.conf master.conf os.conf api.conf"
    echo "id: ${_SALT_MINION_ID}" >> ${_SALT_ETC_DIR}/minion.d/id.conf
    echo "master: ${_SALT_MASTER_ADDRESS}" >> ${_SALT_ETC_DIR}/minion.d/master.conf
    echo "ipc_mode: ipc" >> ${_SALT_ETC_DIR}/minion.d/os.conf
    echo "seapi.url: http://${_SALT_MASTER_ADDRESS}/api/v1" >> ${_SALT_ETC_DIR}/minion.d/api.conf
    echo "certapi.url: http://${_SALT_MASTER_ADDRESS}/api/v1" >> ${_SALT_ETC_DIR}/minion.d/api.conf



    #Download file root_master.pub
    echoinfo "Download file root_master.pub minion"
    __download_file ${_SALT_ETC_DIR}/pki/minion/root_master.pub http://"$_SALT_MASTER_ADDRESS"/serverendpoint/root_master.pub
    __download_file ${_SALT_ETC_DIR}/minion http://"$_SALT_MASTER_ADDRESS"/serverendpoint/salt-minion
#    mv ${_SALT_ETC_DIR}/salt-minion ${_SALT_ETC_DIR}/minion

    #chmod dir install /opt/se
    echoinfo "chmod dir install /opt/se"
    chmod 0755 $_INSTALL_DIR
}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_debian
#   DESCRIPTION:  The big function install for debian
#----------------------------------------------------------------------------------------------------------------------
install_debian(){
    #Create service salt-minion for debian
    __download_file $_INSTALL_DIR/$FILENAME http://"$_SALT_MASTER_ADDRESS"/serverendpoint/"$FILENAME"
    __check_package "unzip"
    CHECK_UNZIP=$?
    if [ "$CHECK_UNZIP" -eq $BS_TRUE ]; then
        unzip -q $FILENAME
    else
        echoerror "Unzip is not installed"
        exit 1
    fi

    #TODO Create service salt-minion for debian
    echoinfo "Create service salt-minion for debian"
    #Download file services
    __download_file $_INSTALL_DIR/service_debian http://"$_SALT_MASTER_ADDRESS"/serverendpoint/service_debian
    echodebug "Format service_debian"
    sed -i "s+DAEMON=/usr/local/sbin/salt-minion+DAEMON=$_INSTALL_DIR/salt-minion+g" $_INSTALL_DIR/service_debian
    sed -i 's+DAEMON_ARGS="-d"+DAEMON_ARGS="-c'$_SALT_ETC_DIR' -d"+g' $_INSTALL_DIR/service_debian
    #chmod dir install (default /opt/se)
    mv $_INSTALL_DIR/service_debian /etc/init.d/salt-minion
    chmod 0755 /etc/init.d/salt-minion


    #create dir pki, config
    echoinfo "Create directory pki, config"
    mkdir -p ${_SALT_ETC_DIR}/minion.d
    mkdir -p ${_SALT_ETC_DIR}/pki/minion
    mkdir -p ${_SALT_ETC_DIR}/pki/master


    #create file config id.conf master.conf os.conf api.conf
    echoinfo "Create file config id.conf master.conf os.conf api.conf"
    echo "id: ${_SALT_MINION_ID}" >> ${_SALT_ETC_DIR}/minion.d/id.conf
    echo "master: ${_SALT_MASTER_ADDRESS}" >> ${_SALT_ETC_DIR}/minion.d/master.conf
    echo "ipc_mode: ipc" >> ${_SALT_ETC_DIR}/minion.d/os.conf
    echo "seapi.url: http://${_SALT_MASTER_ADDRESS}/api/v1" >> ${_SALT_ETC_DIR}/minion.d/api.conf
    echo "certapi.url: http://${_SALT_MASTER_ADDRESS}/api/v1" >> ${_SALT_ETC_DIR}/minion.d/api.conf

    #Download file root_master.pub
    echoinfo "Download file root_master.pub for minion"
    __download_file ${_SALT_ETC_DIR}/pki/minion/root_master.pub http://"$_SALT_MASTER_ADDRESS"/serverendpoint/root_master.pub
    __download_file ${_SALT_ETC_DIR}/minion http://"$_SALT_MASTER_ADDRESS"/serverendpoint/salt-minion
#    mv ${_SALT_ETC_DIR}/salt-minion ${_SALT_ETC_DIR}/minion

    #chmod dir install /opt/se
    echoinfo "chmod dir install /opt/se"
    chmod 0755 $_INSTALL_DIR
}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_ubuntu
#   DESCRIPTION:  The big function install for debian
#----------------------------------------------------------------------------------------------------------------------
install_ubuntu(){
    __download_file $_INSTALL_DIR/$FILENAME http://"$_SALT_MASTER_ADDRESS"/serverendpoint/"$FILENAME"
    __check_package "unzip"
    CHECK_UNZIP=$?
    if [ "$CHECK_UNZIP" -eq $BS_TRUE ]; then
        unzip -q $FILENAME
    else
        echoerror "Unzip is not installed"
        exit 1
    fi

    #TODO Create service salt-minion for debian
    echoinfo "Create service salt-minion for debian"
    #Download file services
    __download_file $_INSTALL_DIR/service_debian http://"$_SALT_MASTER_ADDRESS"/serverendpoint/service_debian
    echodebug "Format service_debian"
    sed -i "s+DAEMON=/usr/local/sbin/salt-minion+DAEMON=$_INSTALL_DIR/salt-minion+g" $_INSTALL_DIR/service_debian
    sed -i 's+DAEMON_ARGS="-d"+DAEMON_ARGS="-c'$_SALT_ETC_DIR' -d"+g' $_INSTALL_DIR/service_debian
    #TODO chmod dir install (default /opt/se)
    mv $_INSTALL_DIR/service_debian /etc/init.d/salt-minion
    chmod 0755 /etc/init.d/salt-minion


    #create dir pki, config
    echoinfo "Create directory pki, config"
    mkdir -p ${_SALT_ETC_DIR}/minion.d
    mkdir -p ${_SALT_ETC_DIR}/pki/minion
    mkdir -p ${_SALT_ETC_DIR}/pki/master


    #create file config id.conf master.conf os.conf api.conf
    echoinfo "Create file config id.conf master.conf os.conf api.conf"
    echo "id: ${_SALT_MINION_ID}" >> ${_SALT_ETC_DIR}/minion.d/id.conf
    echo "master: ${_SALT_MASTER_ADDRESS}" >> ${_SALT_ETC_DIR}/minion.d/master.conf
    echo "ipc_mode: ipc" >> ${_SALT_ETC_DIR}/minion.d/os.conf
    echo "seapi.url: http://${_SALT_MASTER_ADDRESS}/api/v1" >> ${_SALT_ETC_DIR}/minion.d/api.conf
    echo "certapi.url: http://${_SALT_MASTER_ADDRESS}/api/v1" >> ${_SALT_ETC_DIR}/minion.d/api.conf

    #Download file root_master.pub
    echoinfo "Download file root_master.pub minion"
    __download_file ${_SALT_ETC_DIR}/pki/minion/root_master.pub http://"$_SALT_MASTER_ADDRESS"/serverendpoint/root_master.pub
    __download_file ${_SALT_ETC_DIR}/minion http://"$_SALT_MASTER_ADDRESS"/serverendpoint/salt-minion


    #chmod dir install /opt/se
    echoinfo "chmod dir install /opt/se"
    chmod 0755 $_INSTALL_DIR
}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_centos
#   DESCRIPTION:  The big function install for centos
#----------------------------------------------------------------------------------------------------------------------
install_centos(){
    __download_file $_INSTALL_DIR/$FILENAME http://"$_SALT_MASTER_ADDRESS"/serverendpoint/"$FILENAME"
    __check_package "unzip"
    CHECK_UNZIP=$?
    if [ "$CHECK_UNZIP" -eq $BS_TRUE ]; then
        unzip -q $FILENAME
    else
        echoerror "Unzip is not installed"
        exit 1
    fi

    #TODO Create service salt-minion for centos
    echoinfo "Create service salt-minion for centos"
    #Download file services
    __download_file $_INSTALL_DIR/service_centos http://"$_SALT_MASTER_ADDRESS"/serverendpoint/service_centos
    echodebug "Format service_centos"
    sed -i "s+SALTMINION=/usr/local/sbin/salt-minion+SALTMINION=$_INSTALL_DIR/salt-minion+g" $_INSTALL_DIR/service_centos
    sed -i 's+MINION_ARGS=""+MINION_ARGS="-c'$_SALT_ETC_DIR'"+g' $_INSTALL_DIR/service_centos
    #TODO chmod dir install (default /opt/se)
    mv $_INSTALL_DIR/service_centos /etc/init.d/salt-minion
    chmod 0755 /etc/init.d/salt-minion

    #Config auto start service



    #TODO create dir pki, config
    echoinfo "Create dir pki, config"
    mkdir -p ${_SALT_ETC_DIR}/minion.d
    mkdir -p ${_SALT_ETC_DIR}/pki/minion
    mkdir -p ${_SALT_ETC_DIR}/pki/master


    #Create file config id.conf master.conf os.conf api.conf
    echoinfo "create file config id.conf master.conf os.conf api.conf"
    echo "id: ${_SALT_MINION_ID}" >> ${_SALT_ETC_DIR}/minion.d/id.conf
    echo "master: ${_SALT_MASTER_ADDRESS}" >> ${_SALT_ETC_DIR}/minion.d/master.conf
    echo "ipc_mode: ipc" >> ${_SALT_ETC_DIR}/minion.d/os.conf
    echo "seapi.url: http://${_SALT_MASTER_ADDRESS}/api/v1" >> ${_SALT_ETC_DIR}/minion.d/api.conf
    echo "certapi.url: http://${_SALT_MASTER_ADDRESS}/api/v1" >> ${_SALT_ETC_DIR}/minion.d/api.conf



    #Download file root_master.pub
    echoinfo "Download file root_master.pub minion"
    __download_file ${_SALT_ETC_DIR}/pki/minion/root_master.pub http://"$_SALT_MASTER_ADDRESS"/serverendpoint/root_master.pub
    __download_file ${_SALT_ETC_DIR}/minion http://"$_SALT_MASTER_ADDRESS"/serverendpoint/salt-minion


    #chmod dir install /opt/se
    echoinfo "chmod dir install /opt/se"
    chmod 0755 $_INSTALL_DIR
}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_suse
#   DESCRIPTION:  The big function install for centos
#----------------------------------------------------------------------------------------------------------------------
install_suse(){
    __download_file $_INSTALL_DIR http://"$_SALT_MASTER_ADDRESS"/serverendpoint/"$FILENAME"
    __check_package "unzip"
    CHECK_UNZIP=$?
    if [ "$CHECK_UNZIP" -eq $BS_TRUE ]; then
        unzip -q $FILENAME
    else
        echoerror "Unzip is not installed"
        exit 1
    fi

    #TODO Create service salt-minion for centos
    echoinfo "Create service salt-minion for suse"
    #Download file services
    __download_file $_INSTALL_DIR http://"$_SALT_MASTER_ADDRESS"/serverendpoint/service_suse
    echoinfo "Format service_centos"
    sed -i "s+SALTMINION=/usr/local/sbin/salt-minion+SALTMINION=$_INSTALL_DIR/salt-minion+g" $_INSTALL_DIR/service_suse
    sed -i 's+MINION_ARGS=""+MINION_ARGS="-c'$_SALT_ETC_DIR'"+g' $_INSTALL_DIR/service_suse
    #chmod dir install (default /opt/se)
    mv $_INSTALL_DIR/service_centos /etc/init.d/salt-minion
    chmod 0755 /etc/init.d/salt-minion


    #create dir pki, config
    echoinfo "Create directory pki, config"
    mkdir -p ${_SALT_ETC_DIR}/minion.d
    mkdir -p ${_SALT_ETC_DIR}/pki/minion
    mkdir -p ${_SALT_ETC_DIR}/pki/master


    #create file config id.conf master.conf os.conf api.conf
    echoinfo "Create file config id.conf master.conf os.conf api.conf"
    echo "id: ${_SALT_MINION_ID}" >> ${_SALT_ETC_DIR}/minion.d/id.conf
    echo "master: ${_SALT_MASTER_ADDRESS}" >> ${_SALT_ETC_DIR}/minion.d/master.conf
    echo "ipc_mode: ipc" >> ${_SALT_ETC_DIR}/minion.d/os.conf
    echo "seapi.url: http://${_SALT_MASTER_ADDRESS}/api/v1" >> ${_SALT_ETC_DIR}/minion.d/api.conf
    echo "certapi.url: http://${_SALT_MASTER_ADDRESS}/api/v1" >> ${_SALT_ETC_DIR}/minion.d/api.conf

    #Download file root_master.pub
    echoinfo "Download file root_master.pub minion"
    __download_file ${_SALT_ETC_DIR}/pki/minion http://"$_SALT_MASTER_ADDRESS"/serverendpoint/root_master.pub
    __download_file ${_SALT_ETC_DIR}/ http://"$_SALT_MASTER_ADDRESS"/serverendpoint/salt-minion
    mv ${_SALT_ETC_DIR}/salt-minion ${_SALT_ETC_DIR}/minion

    #chmod dir install /opt/se
    echoinfo "chmod dir install /opt/se"
    chmod 0755 $_INSTALL_DIR
}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_centos_post
#   DESCRIPTION:  The post install function for centos
#----------------------------------------------------------------------------------------------------------------------
install_centos_post(){
    if [ -f /bin/systemctl ]; then
        /bin/systemctl is-enabled salt-minion.service > /dev/null 2>&1 || (
#             /bin/systemctl preset salt-minion.service > /dev/null 2>&1 &&
             /bin/systemctl enable salt-minion.service > /dev/null 2>&1
        )
    elif [ -f /etc/init.d/salt-minion ]; then
        /sbin/chkconfig salt-minion on
    fi

    echoinfo "Run synchronization module from syndic"
    sleep 5
    ${_INSTALL_DIR}/salt-call state.highstate -l quiet > /dev/null 2>&1
    count=0
    while [ ! -f "/var/cache/salt/minion/extmods/modules/vsm.py" ] || [ ! -f "/var/cache/salt/minion/extmods/modules/security.py"  ]; do
        echoinfo "Rerun synchronization module from syndic"
        ${_INSTALL_DIR}/salt-call state.highstate -l quiet > /dev/null 2>&1
        count=$((count + 1))
        if [ $count -eq 3 ]; then
            break
        fi
    done

}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_debian_post
#   DESCRIPTION:  The post install function for debian
#----------------------------------------------------------------------------------------------------------------------
install_debian_post(){
    #Config auto start with os
    if [ -f /bin/systemctl ]; then
        # Using systemd
        /bin/systemctl is-enabled salt-minion.service > /dev/null 2>&1 || (
#            /bin/systemctl preset salt-minion.service > /dev/null 2>&1 &&
            /bin/systemctl enable salt-minion.service > /dev/null 2>&1
        )
        sleep 1
        /bin/systemctl daemon-reload
    elif [ -f /etc/init.d/salt-minion ]; then
        update-rc.d salt-minion defaults
    fi
    echoinfo "Run synchronization module from syndic"
    sleep 5
     count=0
    while [ ! -f "/var/cache/salt/minion/extmods/modules/vsm.py" ] || [ ! -f "/var/cache/salt/minion/extmods/modules/security.py"  ]; do
        echoinfo "Rerun synchronization module from syndic"
        ${_INSTALL_DIR}/salt-call state.highstate -l quiet > /dev/null 2>&1
        count=$((count + 1))
        if [ $count -eq 3 ]; then
            break
        fi
    done
}
#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_ubuntu_post
#   DESCRIPTION:  The post install function for debian
#----------------------------------------------------------------------------------------------------------------------
install_ubuntu_post(){
    #Config auto start with os
    if [ -f /bin/systemctl ]; then
        # Using systemd
        /bin/systemctl is-enabled salt-minion.service > /dev/null 2>&1 || (
#            /bin/systemctl preset salt-minion.service > /dev/null 2>&1 &&
            /bin/systemctl enable salt-minion.service > /dev/null 2>&1
        )
        sleep 1
        /bin/systemctl daemon-reload
    elif [ -f /etc/init.d/salt-minion ]; then
        update-rc.d salt-minion defaults
    fi
    echoinfo "Run synchronization module from syndic"
    sleep 5
    ${_INSTALL_DIR}/salt-call state.highstate -l quiet > /dev/null 2>&1
    count=0
    while [ ! -f "/var/cache/salt/minion/extmods/modules/vsm.py" ] || [ ! -f "/var/cache/salt/minion/extmods/modules/security.py"  ]; do
        echoinfo "Rerun synchronization module from syndic"
        ${_INSTALL_DIR}/salt-call state.highstate -l quiet > /dev/null 2>&1
        count=$((count + 1))
        if [ $count -eq 3 ]; then
            break
        fi
    done

}
#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_opensuse_post
#   DESCRIPTION:  The post install function for opensuse
#----------------------------------------------------------------------------------------------------------------------
install_opensuse_post(){
    #Config auto start with os
    if [ -f /bin/systemctl ]; then
        systemctl is-enabled salt-minion.service || ( systemctl enable salt-minion.service)
#        systemctl is-enabled salt-minion.service || (systemctl preset salt-minion.service && systemctl enable salt-minion.service)
        sleep 1
        systemctl daemon-reload
        continue
    fi

    /sbin/chkconfig --add salt-minion
    /sbin/chkconfig salt-minion on
    echoinfo "Run synchronization module from syndic"
    sleep 5
    ${_INSTALL_DIR}/salt-call state.highstate -l quiet > /dev/null 2>&1
    count=0
    while [ ! -f "/var/cache/salt/minion/extmods/modules/vsm.py" ] || [ ! -f "/var/cache/salt/minion/extmods/modules/security.py"  ]; do
        echoinfo "Rerun synchronization module from syndic"
        ${_INSTALL_DIR}/salt-call state.highstate -l quiet > /dev/null 2>&1
        count=$((count + 1))
        if [ $count -eq 3 ]; then
            break
        fi
    done
}
#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_ubuntu_restart_daemons
#   DESCRIPTION:  The restart daemons install function for ubuntu
#----------------------------------------------------------------------------------------------------------------------
install_ubuntu_restart_daemons(){
    if [ -f /bin/systemctl ] && [ "$DISTRO_MAJOR_VERSION" -ge 16 ]; then
        echodebug "There's systemd support while checking salt-minion"
        systemctl stop salt-minion > /dev/null 2>&1
    fi

    if [ -f /sbin/initctl ]; then
        echodebug "There's upstart support while checking salt-minion"
        if status salt-minion 2>/dev/null | grep -q running; then
            stop salt-minion || (echodebug "Fail to stop salt-minion" && return 1)
        fi
        start salt-minion 2>/dev/null && return 1
        echodebug "Failed to start salt-minion using upstart"
    fi

    if [ ! -f /etc/init.d/salt-minion ]; then
        echoerror "No init.d support for salt-minion was found"
        return 1
    fi
    echodebug "Use /etc/init.d for start salt-minion"
    /etc/init.d/salt-minion stop > /dev/null 2>&1
    /etc/init.d/salt-minion start
}
#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_debian_restart_daemons
#   DESCRIPTION:  The restart daemons install function for debian
#----------------------------------------------------------------------------------------------------------------------
install_debian_restart_daemons(){
    if [ -f /bin/systemctl ]; then
        # Debian 8 uses systemd
        /bin/systemctl stop salt-minion > /dev/null 2>&1
        /bin/systemctl start salt-minion.service
    elif [ -f /etc/init.d/salt-minion ]; then
        #still in SysV init
        /etc/init.d/salt-minion stop > /dev/null 2>&1
        /etc/init.d/salt-minion start
    fi
}
#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_debian_stop_daemons
#   DESCRIPTION:  The stop daemons install function for debian
#----------------------------------------------------------------------------------------------------------------------
install_debian_stop_daemons(){
    if [ -f /bin/systemctl ]; then
        # Debian 8 uses systemd
        /bin/systemctl stop salt-minion > /dev/null 2>&1
    elif [ -f /etc/init.d/salt-minion ]; then
        #still in SysV init
        /etc/init.d/salt-minion stop > /dev/null 2>&1
    fi
}
#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_centos_stop_daemons
#   DESCRIPTION:  The stop daemons install function for debian
#----------------------------------------------------------------------------------------------------------------------
install_centos_stop_daemons(){
    if [ -f /bin/systemctl ]; then
        # Debian 8 uses systemd
        /bin/systemctl stop salt-minion > /dev/null 2>&1
    elif [ -f /etc/init.d/salt-minion ]; then
        #still in SysV init
        /etc/init.d/salt-minion stop > /dev/null 2>&1
    fi
}
#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_linux_stop_daemons
#   DESCRIPTION:  The stop daemons install function for linux
#----------------------------------------------------------------------------------------------------------------------
install_linux_stop_daemons(){

    if [ -f /etc/init.d/salt-minion ]; then
        #still in SysV init
        /etc/init.d/salt-minion stop > /dev/null 2>&1
    fi
}
#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_centos_stop_daemons
#   DESCRIPTION:  The stop daemons install function for centos
#----------------------------------------------------------------------------------------------------------------------
install_centos_stop_daemons(){

   if [ -f /sbin/initctl ] && [ -f /etc/init/salt-minion.conf ]; then
        # We have upstart support and upstart knows about our service
        if ! /sbin/initctl status salt-minion > /dev/null 2>&1; then
            # Everything is in place and upstart gave us an error code? Fail!
            return 1
        fi
        # upstart knows about this service.
        # Let's try to stop it, and then start it
        /sbin/initctl stop salt-minion > /dev/null 2>&1

   elif [ -f /etc/init.d/salt-minion ]; then
        # Disable stdin to fix shell session hang on killing tee pipe
        service salt-minion stop < /dev/null > /dev/null 2>&1

   elif [ -f /usr/bin/systemctl ]; then
        # CentOS 7 uses systemd
        /usr/bin/systemctl stop salt-minion > /dev/null 2>&1

   fi
}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_ubuntu_stop_daemons
#   DESCRIPTION:  The stop daemons install function for ubuntu
#----------------------------------------------------------------------------------------------------------------------
install_ubuntu_stop_daemons(){
    if [ -f /bin/systemctl ] && [ "$DISTRO_MAJOR_VERSION" -ge 16 ]; then
        echodebug "There's systemd support while checking salt-minion"
        systemctl stop salt-minion > /dev/null 2>&1
    fi

    if [ -f /sbin/initctl ]; then
        echodebug "There's upstart support while checking salt-minion"
        if status salt-minion 2>/dev/null | grep -q running; then
            stop salt-minion || (echodebug "Fail to stop salt-minion" && return 1)
        fi

    fi

    if [ ! -f /etc/init.d/salt-minion ]; then
        echoerror "No init.d support for salt-minion was found"
        return 1
    fi

    /etc/init.d/salt-minion stop > /dev/null 2>&1

}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_centos_restart_daemons
#   DESCRIPTION:  The restart daemons install function for centos
#----------------------------------------------------------------------------------------------------------------------
install_centos_restart_daemons(){
    if [ -f /sbin/initctl ] && [ -f /etc/init/salt-minion.conf ]; then
        # We have upstart support and upstart knows about our service
        if ! /sbin/initctl status salt-minion > /dev/null 2>&1; then
            # Everything is in place and upstart gave us an error code? Fail!
            return 1
        fi
        # upstart knows about this service.
        # Let's try to stop it, and then start it
        /sbin/initctl stop salt-minion > /dev/null 2>&1
        # Restart service
        if ! /sbin/initctl start salt-minion > /dev/null 2>&1; then
            # Failed the restart?!
            return 1
        fi

    elif [ -f /usr/bin/systemctl ]; then
        # CentOS 7 uses systemd
        systemctl daemon-reload
        /usr/bin/systemctl stop salt-minion > /dev/null 2>&1
        /usr/bin/systemctl start salt-minion.service
    elif [ -f /etc/init.d/salt-minion ]; then
        # Disable stdin to fix shell session hang on killing tee pipe
        service salt-minion stop < /dev/null > /dev/null 2>&1
        service salt-minion start < /dev/null
    fi
}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_linux_restart_daemons
#   DESCRIPTION:  The restart daemons install function for linux
#----------------------------------------------------------------------------------------------------------------------
install_linux_restart_daemons(){
    if [ -f /sbin/initctl ] && [ -f /etc/init/salt-minion.conf ]; then
        # We have upstart support and upstart knows about our service
        if ! /sbin/initctl status salt-minion > /dev/null 2>&1; then
            # Everything is in place and upstart gave us an error code? Fail!
            return 1
        fi
        # upstart knows about this service.
        # Let's try to stop it, and then start it
        /sbin/initctl stop salt-minion > /dev/null 2>&1
        # Restart service
        if ! /sbin/initctl start salt-minion > /dev/null 2>&1; then
            # Failed the restart?!
            return 1
        fi

    elif [ -f /usr/bin/systemctl ]; then
        # CentOS 7 uses systemd
        systemctl daemon-reload
        /usr/bin/systemctl stop salt-minion > /dev/null 2>&1
        /usr/bin/systemctl start salt-minion.service
    elif [ -f /etc/init.d/salt-minion ]; then
        # Disable stdin to fix shell session hang on killing tee pipe
        service salt-minion stop < /dev/null > /dev/null 2>&1
        service salt-minion start < /dev/null
    fi
}
#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_opensuse_restart_daemons
#   DESCRIPTION:  The restart daemons install function for opensuse
#----------------------------------------------------------------------------------------------------------------------
install_opensuse_restart_daemons(){
     if [ -f /bin/systemctl ]; then
        systemctl stop salt-minion > /dev/null 2>&1
        systemctl start salt-minion.service
        return
     fi

     service salt-minion stop > /dev/null 2>&1
     service salt-minion start
}


#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  extract_primary_ip
#   DESCRIPTION:  get the primary ip from server
#----------------------------------------------------------------------------------------------------------------------
extract_primary_ip(){
    _PRIMARY_IP=$(ip addr show 2>/dev/null | grep -oP "(?<=inet ).*(?=/)")
    # echodebug $?
    if [ "$_SALT_ID_SUBNET" = "null" ]; then
        return
    fi
    if [ "$_PRIMARY_IP" = "null" ]; then
        echoerror "Can not found server's ip"
        exit 1
    fi
    for subnet in $_SALT_ID_SUBNET
    do
        echo $subnet
        if [[ $subnet =~ ^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([1-9]|1[0-9]|2[0-9]|3[0-2])$ ]]; then
            for IP in $_PRIMARY_IP
            do
                (( $( __in_subnet $subnet $IP) )) &&
                    echoinfo "${IP} is in ${subnet}"  && _SALT_MINION_ID=$IP && return
            done
        else
            echoerror "$subnet is not correct format! Please config SALT_ID_SUBNET correctly!"
            __usage
            exit 1

        fi
    done

}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_linux_post
#   DESCRIPTION:  The big function post install for all distro linux.
#----------------------------------------------------------------------------------------------------------------------
install_linux_post(){
    if [ -f /bin/systemctl ]; then
        /bin/systemctl is-enabled salt-minion.service > /dev/null 2>&1 || (
#             /bin/systemctl preset salt-minion.service > /dev/null 2>&1 &&
             /bin/systemctl enable salt-minion.service > /dev/null 2>&1
        )
    elif [ -f /etc/init.d/salt-minion ]; then
        /sbin/chkconfig salt-minion on
    fi
    echoinfo "Run synchronization module from syndic"
    sleep 5
    ${_INSTALL_DIR}/salt-call state.highstate -l quiet > /dev/null 2>&1
    count=0
    while [ ! -f "/var/cache/salt/minion/extmods/modules/vsm.py" ] || [ ! -f "/var/cache/salt/minion/extmods/modules/security.py"  ]; do
        echoinfo "Rerun synchronization module from syndic"
        ${_INSTALL_DIR}/salt-call state.highstate -l quiet > /dev/null 2>&1
        count=$((count + 1))
        if [ $count -eq 3 ]; then
            break
        fi
    done
}

#--- FUNCTION  --------------------------------------------------------------------------------------------------------
#          NAME:  install_linux_post
#   DESCRIPTION:  The big function post install for all distro linux.
#----------------------------------------------------------------------------------------------------------------------
install_linux_other_agents(){
    if [ $_INSTALL_FILEBEAT -eq $BS_TRUE ]; then
        echoinfo "Running install filebeat"
        __download_file $_INSTALL_DIR/deploy_agent.sh http://$_SALT_MASTER_ADDRESS/serverendpoint/logagent/deploy_agent.sh
        mv -f $_INSTALL_DIR/deploy_agent.sh /root/deploy_agent.sh
        bash /root/deploy_agent.sh > /opt/se/deploy.txt >> /dev/null 2>&1
    fi

}

#---  MAIN FUNCTION  --------------------------------------------------------------------------------------------------
#          NAME:  __main__
#   DESCRIPTION:  The first function is call by script
#----------------------------------------------------------------------------------------------------------------------
__main__(){
    __whoami
    __get_caller

    #Display SE infomation
    echoinfo "Running version: ${__ScriptVersion}"
    echoinfo "Executed by: ${CALLER}"
    echoinfo "Command line: '${__ScriptFullName} ${__ScriptArgs}'"
    echoinfo "Running the ${__ScriptName}"

    # Check for any unparsed arguments. Should be an error.
    if [ "$#" -gt 0 ]; then
        __usage
        echo
        echoerror "Too many arguments."
        exit 1
    fi


    __gather_hardware_info
    __gather_os_info
    __gather_system_info


    #Display OS, Architect
    echo
    echoinfo "System Information:"
    echoinfo "  CPU:          ${CPU_VENDOR_ID}"
    echoinfo "  CPU Arch:     ${CPU_ARCH}"
    echoinfo "  OS Name:      ${OS_NAME}"
    echoinfo "  OS Version:   ${OS_VERSION}"
    echoinfo "  Distribution: ${DISTRO_NAME} ${DISTRO_VERSION}"

    echo
    echoinfo "SE Config Information:"
    echoinfo "  Server id: ${_SALT_MINION_ID}"
    echoinfo "  Master ip: ${_SALT_MASTER_ADDRESS}"
    echodebug " Salt id subnet: ${_SALT_ID_SUBNET}"

    echo
    echoinfo "Prepare Installation Phase"
    __simplify_distro_and_prefix_version
    __check_end_of_life_versions

    if [ $CPU_ARCH != "x86_64" ]; then
       echoerror "This file setup not support server 32bit."
       exit 1
    fi

    __check_dependence
    __validate_master_ip
    __validate_server_id
    __is_se_installed
    IS_SE_INSTALL=$?
    if [ $IS_SE_INSTALL -eq $BS_TRUE ]; then
        if [  $_FORCE_INSTALL -eq $BS_TRUE  ]; then
            __get_stop_deamons_function
            echoinfo "Running ${STOP_DAEMONS_FUNC}!!!"
            if ! ${STOP_DAEMONS_FUNC}; then
                echowarn "Failed to run ${STOP_DAEMONS_FUNC}()!!!"
            fi
            __uninstall
        else
            echoerror "Server endpoint is installed! Use -f option to force install."
            __usage
            exit 1
        fi
    fi
    mkdir -p ${_INSTALL_DIR}
    cd ${_INSTALL_DIR}
    echo


    echoinfo "Installation Phase"
    __get_install_function
#   #Running All Function for this distro
    echoinfo "Running ${INSTALL_FUNC}()"
    if ! ${INSTALL_FUNC}; then
        echoerror "Failed to run ${INSTALL_FUNC}()!!!"
        exit 1
    fi



    echo
    echoinfo "Post Installation Phase"
    __get_post_install_function
    # Run any post install function
    if [ "$POST_INSTALL_FUNC" != "null" ]; then
        echoinfo "Running ${POST_INSTALL_FUNC}()"
        if ! ${POST_INSTALL_FUNC}; then
            echoerror "Failed to run ${POST_INSTALL_FUNC}()!!!"
            exit 1
        fi
    fi

    echo
    echoinfo "Install Other Agent Phase"
     __get_install_other_agent_function
    # Install other agents
    if [ "$INSTALL_OTHER_AGENTS_FUNC" != "null" ]; then
        echoinfo "Running ${INSTALL_OTHER_AGENTS_FUNC}()"
        if ! ${INSTALL_OTHER_AGENTS_FUNC}; then
            echoerror "Failed to run ${INSTALL_OTHER_AGENTS_FUNC}()!!!"
            exit 1
        fi
    fi


    echo
    echoinfo "Restart Daemon Phase"
    __get_install_restart_daemons_function
    # Run any start daemons function
    if [ "$STARTDAEMONS_INSTALL_FUNC" != "null" ]; then
        echoinfo "Running ${STARTDAEMONS_INSTALL_FUNC}()"
        echodebug "Waiting ${_SLEEP} seconds for processes to settle before checking for them"
        sleep ${_SLEEP}
        if ! ${STARTDAEMONS_INSTALL_FUNC}; then
            echoerror "Failed to run ${STARTDAEMONS_INSTALL_FUNC}()!!!"
            exit 1
        fi
    fi


    echo
    se_version=$( ${_INSTALL_DIR}/salt-call test.version -l quiet | grep -oP "(\d+.\d+.\d+)" )
    echoinfo "Version SE is $se_version"
    echoinfo "Finish installation."
}
__main__