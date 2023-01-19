#!/bin/bash

# Java installation paths
jdk_base_path='/Library/Java/JavaVirtualMachines'
jre_base_path='/Library/Internet Plug-Ins' # Alright! Whose idea was it to have folder names with spaces?

# temp folders
temp_download_dir=$(mktemp -d)
temp_unpack_dir="$temp_download_dir/temurin"
mkdir -p "$temp_unpack_dir"

cleanup() {
    rm -rf "$temp_download_dir"
}
trap cleanup EXIT

# Adoptium API
adoptium_api=https://api.adoptium.net

# Does user need to update JAVA_HOME?
java_home_version=

# formatted output
b=$(tput bold)
ul=$(tput smul)
cr=$(tput setaf 1)
cg=$(tput setaf 2)
cy=$(tput setaf 3)
cb=$(tput setaf 4)
n=$(tput sgr0) # reset terminal to default

header() {
    echo "${b}${cb}<< ${1} >>"
    echo "${n}"
}

fatal() {
    echo >&2 "${cr}ERROR:${n} ${1}"
    exit 23
}

ask_user() {
    local answer
    local question
    question=$1

    while [ -z "$answer" ]; do
        echo -n "$question [y/n] "
        read -r -s -n 1 answer < /dev/tty
        echo "$answer"
        if [[ "$answer" != 'y' && "$answer" != 'n' ]]; then
            echo "Please answer with either 'y' or 'n'!"
            answer=
        fi
    done

    if [ "$answer" = 'y' ]; then
        true
    else
        false
    fi
}

ask_user_info() {
    local answer
    local question
    question=$1

    while [ -z "$answer" ]; do
        echo -n "$question [y/n] (or [i] if you need more info) "
        read -r -s -n 1 answer < /dev/tty
        echo "$answer"
        if [[ "$answer" != 'y' && "$answer" != 'n' && "$answer" != 'i' ]]; then
            echo "Please answer with either 'y', 'n', or 'i'!"
            answer=
        fi
    done

    case "$answer" in
        y)
        return 0
        ;;
        n)
        return 1
        ;;
        i)
        return 2
        ;;
    esac
}

# maps output of 'uname -m' to architecture strings used by Temurin
map_architecture() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        'x86_64')
            echo 'x64'
            ;;
        'arm64')
            echo 'aarch64'
            ;;
        *)
            fatal "Unsupported processor architecture: $arch"
            ;;
    esac
}

starts_with() { case $2 in "$1"*) true;; *) false;; esac; }

check_can_connect() {
    curl -s -I -o /dev/null -f "${adoptium_api}"
}

download_temurin() {
    local feature_version
    local package # either 'jre' or jdk
    local url
    local status_code

    feature_version="$1"
    package="$2"

    url="${adoptium_api}/v3/binary/latest/${feature_version}/ga/mac/$(map_architecture)/${package}/hotspot/normal/eclipse"
    status_code=$(curl -s -w '%{http_code}' -o /dev/null "$url")

    if [ "$status_code" != '307' ]; then
        echo "${cr}${b}Failed to get download URL for Temurin Java $feature_version ($package)!${n}"
        return 1
    fi
    
    curl -# -L -o "${temp_download_dir}/Temurin-${feature_version}.tgz" "$url"
    return $?
}

discover_java_exes() {
    local flavor #either 'oracle' or 'openjdk'
    local package # 'jre' or 'jdk'
    local java_exes
    local exec_cmd
    local base_path

    flavor=$1
    package=$2
    if [ "$flavor" = 'oracle' ]; then
        if [ "$package" = 'jdk' ]; then
            # shellcheck disable=SC2016
            exec_cmd='JBIN="{}"; "$JBIN" -version 2>&1 | grep -q "^Java(TM)" && test -f "${JBIN}c" && echo "$JBIN"'
        else
            # shellcheck disable=SC2016
            exec_cmd='JBIN="{}"; "$JBIN" -version 2>&1 | grep -q "^Java(TM)" && echo "$JBIN"'
        fi
    else
        if [ "$package" = 'jdk' ]; then
            # shellcheck disable=SC2016
            exec_cmd='JBIN="{}"; "$JBIN" -version 2>&1 | grep -q "^OpenJDK Runtime" && test -f "${JBIN}c" && echo "$JBIN"'
        else
            # shellcheck disable=SC2016
            exec_cmd='JBIN="{}"; "$JBIN" -version 2>&1 | grep -q "^OpenJDK Runtime" && echo "$JBIN"'
        fi
    fi

    if [ "$package" = 'jre' ] && [ "$flavor" = 'oracle' ]; then
        base_path=$jre_base_path
    else
        base_path=$jdk_base_path
    fi

    java_exes=$(find "$base_path" -type f -name java -exec bash -c "$exec_cmd" \;)
    echo "$java_exes"
}

get_java_folder() {
    local folder
    folder=${1##"${jdk_base_path}"/}
    folder=${folder%%/*}
    echo "$folder"
}

get_java_version() {
    local java_exe="$1"
    "$java_exe" -version 2>&1 | head -1 | cut -d ' ' -f 3 | tr -d '"'
}

get_java_feature_version() {
    local full_version=$1
    local major
    local minor
    major=$(echo "$full_version" | cut -d '.' -f 1)
    minor=$(echo "$full_version" | cut -d '.' -f 2)

    if [ "$major" = '1' ]; then
        echo "$minor" # Should work for all Java versions < 11
    else
        echo "$major" # Should work for all Java versions >= 11
    fi
}

is_new_lic() {
    local full_version=$1
    local feature_version
    local update
    feature_version=$(get_java_feature_version "$full_version")

    if [ "$feature_version" -gt 8 ]; then
        true
    elif [ "$feature_version" -lt 8 ]; then
        false
    else
        update=$(echo "$full_version" | cut -d '_' -f 2)
        if [ "$update" -gt 202 ]; then
            true
        else
            false
        fi
    fi
}

check_java_home() {
    local path
    path=$1
    if test -n "$JAVA_HOME" && starts_with "$JAVA_HOME" "$path"; then
        echo "${cy}JAVA_HOME pointing to Oracle Java!${n}"
        echo ''
        echo "It seems that JAVA_HOME is pointing to the copy of Oracle Java that you asked me to remove:"
        echo ''
        echo "  ${b}JAVA_HOME=${JAVA_HOME}${n}"
        echo ''
        echo "Updating JAVA_HOME is out of this script's scope. If you intend to proceed with the removal"
        echo "it is your responsibility to modify JAVA_HOME afterwards."
        echo ''
        if ask_user 'Do you still want to proceed with the removal?'; then
            java_home_version=$(get_java_version "$path")
            return 0
        else
            return 1
        fi
    fi

    return 0
}

unpack_temurin() {
    local feature_version
    local package
    local dest_dir

    feature_version="$1"
    package="$2"

    dest_dir="${jdk_base_path}/temurin-${feature_version}.${package}"

    if [ -d "$dest_dir" ]; then
        echo "${cy}The destination directory ${b}${dest_dir}${n} ${cy}already exists on the system.${n}"
        echo "If you proceed, the directory must be deleted first.${n}"
        if ! ask_user 'Do you want to continue?'; then
            return 1
        else
            sudo rm -rf "${dest_dir}" || return $?
        fi
    fi

    tar -C "${temp_unpack_dir}" -x -f "${temp_download_dir}/Temurin-${feature_version}.tgz" 2> /dev/null || return $?
    sudo mv "${temp_unpack_dir}"/* "$dest_dir" || return $?
    sudo chown -R root:wheel "${jdk_base_path}/temurin-${feature_version}.${package}" || return $?
}

install_temurin() {
    local feature_version
    local package # either 'jre' or jdk
    local package_hr

    feature_version="$1"
    package="$2"
    package_hr=$(echo "$package" | tr '[:lower:]' '[:upper:]')

    if [ "$package" != 'jre' ] && [ "$package" != 'jdk' ]; then
        fatal "'package' must be either 'jre' or 'jdk' but was: $package"
    fi

    echo "‣ Downloading Temurin $(echo "$package" | tr '[:lower:]' '[:upper:]') $feature_version."
    while ! download_temurin "$feature_version" "$package"; do
        echo "${cr}Failed to download Temurin $package_hr ${feature_version}!${n}"

        if ! ask_user 'Do you want to try again?'; then
            echo 'Giving up!'
            return 1
        fi
    done

    echo "‣ Installing Temurin $package_hr $feature_version."
    while ! unpack_temurin "$feature_version" "$package"; do
        # shellcheck disable=SC2059
        printf "\n${cr}Failed to extract Temurin binaries!${n}\n"
        if ! ask_user 'Do you want to try again?'; then
            echo 'Giving up!'
            return 1
        fi
    done
    echo "${cg}${b}Temurin $package_hr successfully installed!${n}"
}

nuke_oracle_jdk() {
    local java_folder
    local rv
    java_folder=$(get_java_folder "$1")

    pushd "$jdk_base_path" 1> /dev/null || { fatal 'Failed to change working directory!'; }
    sudo rm -rf "$java_folder" > /dev/null; rv=$?
    popd 1> /dev/null || { fatal 'Failed to return to previous working directory!'; }
}

# JRE related
install_temurin_jre() {
    install_temurin 8 jre
}

nuke_oracle_jre() {
    local rv=0

    if [ -d '/Library/Internet Plug-Ins/JavaAppletPlugin.plugin' ]; then
        echo "‣ Removing ${b}/Library/Internet Plug-Ins/JavaAppletPlugin.plugin${n} (you might need to enter your password)"
        sudo rm -rf '/Library/Internet Plug-Ins/JavaAppletPlugin.plugin' 2> /dev/null || { echo "${cr}${b}  Failed to delete folder!${n}"; rv=1; }
    fi

    if [ -d '/Library/PreferencePanes/JavaControlPanel.prefPane' ]; then
        echo "‣ Removing ${b}/Library/PreferencePanes/JavaControlPanel.prefPane${n} (you might need to enter your password)"
        sudo rm -rf '/Library/PreferencePanes/JavaControlPanel.prefPane' 2> /dev/null || { echo "${cr}${b}  Failed to delete folder!${n}"; rv=2; }
    fi

    if [ -d "$HOME/Library/Application Support/Oracle/Java" ]; then
        echo "‣ Removing ${b}$HOME/Library/Application Support/Oracle/Java${n}"
        rm -rf "$HOME/Library/Application Support/Oracle/Java" 2> /dev/null || { echo "${cr}${b}  Failed to delete folder!${n}"; rv=3; }
    fi

    # It seems that Oracle JRE is recording its last usage in a file stored in a hidden folder in user's HOME. Hm...
    if [ -d "$HOME/.oracle_jre_usage" ]; then
        echo "‣ Removing ${b}$HOME/.oracle_jre_usage${n}"
        rm -rf "$HOME/.oracle_jre_usage" 2> /dev/null || { echo "${cr}${b}  Failed to delete folder!${n}"; rv=4; }
    fi

    return $rv
}

has_oracle_jre() {
    local jre_bin

    # In case of the Oracle JRE, there can only ever be one.
    jre_bin="$(discover_java_exes 'oracle' 'jre')"
    
    if [ -n "$jre_bin" ]; then
        echo "$jre_bin"
        return 0
    fi
    
    return 1
}

has_temurin_jre() {
    test -d "$jdk_base_path/temurin-8.jre" && test -f "$jdk_base_path/temurin-8.jre/Contents/Home/bin/java"
}

has_oracle_jre_remnants() {
    test -d '/Library/Internet Plug-Ins/JavaAppletPlugin.plugin' || \
    test -d '/Library/PreferencePanes/JavaControlPanel.prefPane' || \
    test -d "$HOME/Library/Application Support/Oracle/Java" || \
    test -d "$HOME/.oracle_jre_usage"
}

jre_info() {
    echo ''
    echo "It looks like you have the Oracle JRE installed. Apart from the JVM, Oracle's JRE"
    echo "ships with two components that never have been open-sourced:"
    echo ''
    echo '  • support for Java applets (run Java applications inside a browser)'
    echo '  • support for Java Web Start (start Java applications from within a browser)'
    echo ''
    echo 'As Temurin JRE cannot include these proprietary extensions, it is not a 1:1 replacement'
    echo 'for Oracle. That said, Java applets are deprecated for a long time and it is unlikely'
    echo 'that you still need this functionality.'
    echo ''
    echo 'Java Web Start is deprecated too as of Java 9, however it is still used sometimes.'
    echo 'If you still need support for Java Web Start, I would recommend that you check out'
    echo 'Open Web Start (https://openwebstart.com/) which offers an open source replacement'
    echo 'for Java Web Start.'
    echo ''
    echo 'If you have the JRE installed because you just need a Java runtime environment without'
    echo 'any of the developer tools, then replacing the Oracle JRE with Temurin should be fine.'
    echo ''
}

deprecated_version_info() {
    echo "Java 7 ${cy}${b}is no longer supported${n} and Temurin does not provide builds for it."
    echo 'Replacing it with Java 8 is likely a safe and sane option. That said, there is a'
    echo 'slim chance that some older Java applications will not run properly under Java 8.'
    echo ''
}

ancient_version_info() {
    echo ''
    echo "${cr}It looks like you have Oracle JRE 6 installed. This Java version is very old"
    echo 'and was distributed directly by Apple for macOS 10.13 or older.'
    echo 'Java 6 is no longer supported by Apple (and neither is macOS 10.13).'
    echo 'This script was never tested with Java 6 on macOS 10.13 or older and will therefore exit now.'
    echo ''
    echo 'It is highly recommended that you update your macOS installation to a supported release.'
    echo "Once done, you may re-run this script.${n}"
    echo ''
}

new_lic_info() {
    echo "${cy}As of April 16, 2019, Oracle has changed the license under which Java is released."
    echo "Under the new conditions certain uses, such as personal use and development use are still"
    echo "allowed at no cost, yet other uses authorized under the prior license terms are ${b}no longer free.${n}"
    echo ""
    echo "${cy}It is highly recommended that you replace this version of Java with Eclipse Temurin, particularly"
    echo "if you use it in a commercial setting.${n}"
    echo ''
}

deal_with_jre() {
    local jre_bin
    local full_version
    local feature_version

    header 'Java Runtime Environment (JRE)'
    echo "${ul}Oracle JRE${n}: Looking for an installation of Oracle JRE on the system."
    jre_bin="$(has_oracle_jre)"

    if [ -n "$jre_bin" ]; then
        full_version=$(get_java_version "$jre_bin")
        feature_version=$(get_java_feature_version "$full_version")
        # shellcheck disable=SC2059
        printf "${cy}Found ${b}Oracle JRE ${feature_version} (${full_version})${n}"

        if [ "$feature_version" -lt 8 ]; then
            # shellcheck disable=SC2059
            printf "${cy} (deprecated version)!${n}\n\n"
        elif is_new_lic "$full_version"; then
            # shellcheck disable=SC2059
            printf "${cr} (new license)!${n}\n\n"
        else
            # shellcheck disable=SC2059
            printf "${cy}!${n}\n\n"
        fi

        local replace_it='?'
        local response
        ask_user_info 'Do you want to replace Oracle JRE with Temurin JRE?'; response=$?
        if [ $response -eq 0 ]; then
            replace_it='y'
        elif [ $response -eq 1 ]; then
            replace_it='n'
        else
            jre_info

            if [ "$feature_version" -lt 8 ]; then
                printf 'Further: '
                deprecated_version_info
            elif is_new_lic "$full_version"; then
                printf 'Important: '
                new_lic_info
            fi

            if ask_user 'Do you want to replace Oracle JRE with Temurin JRE?'; then
                replace_it='y'
            else
                replace_it='n'
            fi
        fi

        if [ "$replace_it" = 'y' ]; then
            # shellcheck disable=SC2059
            printf "\n${ul}Replacement${n}: Installing Temurin JRE if necessary.\n"
            echo '‣ Checking if Temurin JRE is already installed.'
            if ! has_temurin_jre; then
                echo "${cy}Not found! Will download and install Temurin JRE.${n}"
                if ! install_temurin_jre; then
                    echo "${cr}Installation of Temurin JRE failed. Won't remove Oracle JRE!${n}"
                    return 1
                fi
            else
                echo "${cg}Found! Skipping download and installation.${n}"
            fi

            # shellcheck disable=SC2059
            printf "\n${ul}Removal${n}: Deleting Oracle JRE.\n"
            if check_java_home "$jre_bin"; then
                test -n "$java_home_version" && java_home_version='JRE'
                if nuke_oracle_jre; then
                    echo "${cg}${b}Oracle JRE removed!${n}"
                else
                    echo "${cy}It seems that I could not fully remove Oracle JRE!${n}"
                fi
            else
                echo "${cr}Removal of Oracle JRE failed!${n}"
            fi
        else
            echo 'Your choice! I will leave everything as is.'
        fi
    else
        # shellcheck disable=SC2059
        printf "${cg}${b}No installation found!${n}\n\n"
        echo "${ul}Leftovers${n}: Checking if remnants of a previous JRE installation are still around."
        if has_oracle_jre_remnants; then
            # shellcheck disable=SC2059
            printf "${cy}${b}Found something!${n}\n\n"
            echo 'I found some remnants from a previous installation of Oracle JRE that can be safely deleted.'
            if ask_user 'Do you want me to remove them?'; then
                echo ''
                if nuke_oracle_jre; then
                    echo "${cg}${b}All remnants removed!${n}"
                else
                    echo "${cy}${b}It seems that not all remnants could be removed!${n}"
                fi
            else
                echo "Fine! I won't touch anything!"
            fi
        else
            echo "${cg}${b}No remnants found!${n}"
        fi
    fi
}
# end JRE related

# JDK related
deal_with_jdks() {
    local oracle_jdks
    local openjdk_jdks
    local openjdk_feature_versions
    local to_remove
    local to_replace
    local full_ver
    local major_ver

    oracle_jdks=()
    openjdk_jdks=()
    openjdk_feature_versions=()
    to_remove=()
    to_replace=()

    header 'Java Development Kits (JDK)'
    echo "${ul}OpenJDK${n}: Looking for OpenJDK installations on the system."
    
    while IFS='' read -r line; do test -n "$line" && oracle_jdks+=("$line"); done < <(discover_java_exes 'oracle' 'jdk')
    while IFS='' read -r line; do test -n "$line" && openjdk_jdks+=("$line"); done < <(discover_java_exes 'openjdk' 'jdk')

    if [ ${#openjdk_jdks[@]} -gt 0 ]; then
        for oj in "${openjdk_jdks[@]}"; do
            full_ver=$(get_java_version "$oj")
            major_ver=$(get_java_feature_version "$full_ver")
            echo "‣ Found ${b}OpenJDK $major_ver ($full_ver)${n}."
            openjdk_feature_versions+=("$major_ver")
        done
    else
        echo 'No OpenJDK installations found.'
    fi

    # shellcheck disable=SC2059
    printf "\n${ul}Oracle JDKs${n}: Looking for installations of Oracle JDKs on the system.\n"
    if [ ${#oracle_jdks[@]} -gt 0 ]; then

        for oj in "${oracle_jdks[@]}"; do
            local replace
            replace='yes'
            full_ver=$(get_java_version "$oj")
            major_ver=$(get_java_feature_version "$full_ver")
            # shellcheck disable=SC2059
            printf "‣ Found ${b}Oracle JDK $major_ver ($full_ver)${n}"

            if [ "$major_ver" -lt 8 ]; then
                echo "${cy} (deprecated version)!${n}"
            elif is_new_lic "$full_ver"; then
                echo "${cr} (new license)!${n}"
            else
                echo '!'
            fi

            for openjdk_major in "${openjdk_feature_versions[@]}"; do
                if [ "$openjdk_major" = "$major_ver" ]; then # OpenJDK already available
                    replace='no'
                fi

                if [ "$major_ver" -lt 8 ] && [ "$openjdk_major" -eq 8 ]; then
                    replace='no'
                fi
            done

            if [ "$replace" = 'yes' ]; then
                if [ "$major_ver" -lt 8 ] || is_new_lic "$full_ver"; then
                    local response
                    ask_user_info "Do you want to replace Oracle JDK ${major_ver} with Temurin JDK 8?"; response=$?

                    if [ "$response" -eq 0 ]; then
                        to_replace+=("$oj")
                    elif [ "$response" -eq 2 ]; then
                        echo ''
                        if [ "$major_ver" -lt 8 ]; then
                            deprecated_version_info
                        else
                            new_lic_info
                        fi

                        if ask_user "Do you want to replace Oracle JDK ${major_ver} with Temurin OpenJDK 8?"; then
                            to_replace+=("$oj")
                        fi
                    fi
                else
                    if ask_user "Do you want to replace it with Temurin OpenJDK ${major_ver}?"; then
                        to_replace+=("$oj")
                    fi
                fi
            else
                if [ "$major_ver" -lt 8 ]; then
                    echo "It seems that an OpenJDK 8 installation that can replace ${b}Oracle Java ${major_ver}${n} already exists."
                    local response
                    ask_user_info "Do you therefore want to uninstall Oracle JDK ${major_ver}?"; response=$?
                    if [ "$response" -eq 0 ]; then
                        to_remove+=("$oj")
                    elif [ "$response" -eq 2 ]; then
                        echo ''
                        deprecated_version_info
                        if ask_user "Based on this info, do you want to uninstall Oracle JDK ${major_ver}?"; then
                            to_remove+=("$oj")
                        fi
                    fi
                else
                    echo "It seems that an OpenJDK installation for ${b}Java ${major_ver}${n} already exists."
                    if ask_user "Do you want to uninstall Oracle JDK ${major_ver}?"; then
                        to_remove+=("$oj")
                    fi
                fi
            fi
        done

        # shellcheck disable=SC2059
        test ${#to_replace[@]} -gt 0 && printf "\n${ul}Replacement${n}: Installing Temurin JDKs as replacement for Oracle JDKs.\n"
        local jdk_8_installed
        jdk_8_installed='no'
        for replace_me in "${to_replace[@]}"; do
            full_ver=$(get_java_version "$replace_me")
            major_ver=$(get_java_feature_version "$full_ver")

            if [ "$major_ver" -lt 8 ]; then
                major_ver=8
            fi

            if [ "$major_ver" -eq 8 ] && [ "$jdk_8_installed" = 'yes' ]; then
                to_remove+=("$replace_me")
                continue
            fi

            if install_temurin "$major_ver" 'jdk'; then
                jdk_8_installed='yes'
                to_remove+=("$replace_me")
            else
                echo "${cr}Installation of Temurin JDK failed. Won't remove Oracle JDK!${n}"
            fi
        done

        # shellcheck disable=SC2059
        test ${#to_remove[@]} -gt 0 && printf "\n${ul}Removal${n}: Deleting Oracle JDKs.\n"
        for rm_me in "${to_remove[@]}"; do
            full_ver=$(get_java_version "$rm_me")
            major_ver=$(get_java_feature_version "$full_ver")
            echo "‣ Removing Oracle JDK $major_ver ($full_ver) (you might need to enter your password)"
            if check_java_home "$rm_me"; then
                if nuke_oracle_jdk "$rm_me"; then
                    echo "${cg}${b}Removed Oracle JDK!${n}"
                else
                    echo "${cy}${b}Failed to remove Oracle JDK!${n}"
                fi
            else
                echo "${cy}${b}Aborted removal of Oracle JDK!${n}"
            fi
        done
    else
        echo "${cg}${b}No Oracle JDKs found!${n}"
    fi
}
# end JDK related

# pre checks
print_default_java_details() {
    local version
    local feature_version
    # Note: macOS always has the /usr/bin/java shim. Therefore we cannot simply check for the presence of 'java' on the PATH.
    # Likewise, we shouldn't call /usr/bin/java directly since an annoying message box will pop up if no JRE or JDK is installed.
    echo "${ul}Default Installation${n}: Looking for a default Java installation and checking JAVA_HOME."

    if /usr/libexec/java_home &> /dev/null; then
        # Okay to go via the shim here
        version=$(get_java_version '/usr/bin/java')
        feature_version=$(get_java_feature_version "$version")
        echo "‣ It looks like at least one version of Java is installed: ${b}Java ${feature_version} ($version)${n}"

        if [ "$feature_version" -lt 7 ]; then
            ancient_version_info
            exit 1
        fi
    else
        echo "‣ Could not find a default Java installation."
    fi

    if [ -n "$JAVA_HOME" ]; then
        echo "‣ It looks like the environment variable JAVA_HOME is set and it is pointing to ${b}${JAVA_HOME}${n}"
    else
        echo "‣ It seems that the environment variable JAVA_HOME is not set."
    fi
    echo ''
}

can_reach_adoptium_api() {
    echo "${ul}Connectivity${n}: Trying to reach the Adoptium API at ${b}${adoptium_api}${n}."
    if ! check_can_connect; then
        echo "${cr}${b}Failed to connect!${n}"
        echo "${cy}"
        echo "Trying to connect to ${adoptium_api} resulted in an error."
        echo "This script requires an active Internet connection to proceed."
        echo "Please verify that your machine is connected to the Internet"
        echo "and that it can connect to ${adoptium_api}."
        echo "${n}"
        echo 'Exiting now!'
        exit 1
    else
       echo "${cg}${b}Excellent! Adoptium API is responding!${n}"
    fi
}

user_is_admin() {
    echo "${ul}Admin Rights${n}: Confirming that your account has admin rights."
    echo "(If a prompt appears below, please enter your password now.)"
    if ! sudo ls /Library &> /dev/null; then
        echo "${cr}${b}Failed to execute test command as admin!${n}"
        echo "${cy}"
        echo 'Unless you have mistyped your password too many times this means that'
        echo 'your account does not have the required privileges to run this script.'
        echo "Please execute it under an account with admin privileges.${n}"
        echo ''
        echo 'Exiting now!'
        exit 2
    else
        echo "${cg}${b}Swell! Your account can run commands as admin!${n}"
    fi
    echo ''
}

prechecks() {
    header 'Initial Checks'
    print_default_java_details
    user_is_admin
    can_reach_adoptium_api
}

get_java_home() {
    local jhome="$1"
    jhome=${jhome%%/bin/java}
    echo "$jhome"
}

post() {
    local prev_feature_version
    local new_java_home

    if [ -n "$java_home_version" ]; then
        header 'Updating JAVA_HOME'

        echo "${ul}New location${n}: Finding the appropriate value for JAVA_HOME."

        if [ "$java_home_version" = 'JRE' ]; then
            has_temurin_jre && new_java_home="$jdk_base_path/temurin-8.jre/Contents/Home"
        else
            prev_feature_version=$(get_java_feature_version "$java_home_version")

            for j in $(discover_java_exes 'openjdk' 'jdk'); do
                local ver
                local fver
                ver=$(get_java_version "$j")
                fver=$(get_java_feature_version "$ver")
                if [ "$fver" = "$prev_feature_version" ]; then
                    new_java_home=$(get_java_home "$j")
                fi
            done
        fi

        if [ -z "$new_java_home" ]; then
            # Kind of unexpected
            echo "${cy}Failed to find the proper location! Falling back to ${b}/usr/libexec/java_home${n}"
            new_java_home="$(/usr/libexec/java_home)"
        fi

        echo ''
        echo "The location JAVA_HOME is pointing to (${b}${JAVA_HOME}${n}) no longer exists"
        echo "and you should updated JAVA_HOME accordingly. JAVA_HOME is typically set in one"
        echo "of the following files:"
        # shellcheck disable=SC2016
        echo '  ‣ $HOME/.zshenv'
        # shellcheck disable=SC2016
        echo '  ‣ $HOME/.zprofile'
        # shellcheck disable=SC2016
        echo '  ‣ $HOME/.basrc'
        # shellcheck disable=SC2016
        echo '  ‣ $HOME/.bash_profile'
        echo ''
        echo 'Once you have figured out in which file JAVA_HOME gets set, you may then edit'
        echo 'the file and update JAVA_HOME:'
        echo "${b}export JAVA_HOME='$new_java_home'${n}"
        echo ''
        echo "Note that on macOS ${b}/usr/libexec/java_home${n} is sometimes used to dynamically"
        echo 'set JAVA_HOME. In this case, the line in the config file might look like this:'
        echo "${b}export JAVA_HOME=\$(/usr/libexec/java_home)${n}"
        echo ''
        echo "If this is the case, you can leave the file untouched."
    fi
}

{
    prechecks
    echo ''
    deal_with_jre
    echo ''
    deal_with_jdks
    echo ''
    post
}

