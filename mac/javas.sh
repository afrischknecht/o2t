#!/bin/bash

# Alright! Whose idea was it to have folder names with spaces?
jdk_base_path='/Library/Java/JavaVirtualMachines'
jre_base_path='/Library/Internet Plug-Ins'

# temp folders
temp_download_dir=$(mktemp -d)
temp_unpack_dir="$temp_download_dir/temurin"
mkdir -p "$temp_unpack_dir"

# Adoptium API 
adoptium_api=https://api.adoptium.net

# colored output
esc=$'\033'
csi="${esc}["
info="${csi}0;32mINFO:${csi}0m"
warning="${csi}0;33mWARNING:${csi}0m"
error="${csi}0;31mERROR:${csi}0m"

cleanup() {
    rm -rf "$temp_download_dir"
}
trap cleanup EXIT

echo_g() { echo "${csi}0;32m${1}${csi}0m"; }

echo_r() { echo "${csi}0;31m${1}${csi}0m"; }

echo_y() { echo "${csi}0;33m${1}${csi}0m"; }

ask_user() {
    local answer
    local question
    question=$1

    while [ -z "$answer" ]; do
        echo -n "$question [y/n]"
        read -r -s -n 1 answer
        echo " $answer"
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
            echo >&2 "$error Unsupported processor architecture: $arch"
            exit 1
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
        echo >&2 "$error Failed to get download URL for Temurin Java $feature_version ($package)!"
        return 1
    fi
    
    echo "$info Downloading Temurin Java $feature_version ($package)..."
    curl -# -L -o "${temp_download_dir}/Temurin-${feature_version}.tgz" "$url" || return $?
}

unpack_temurin() {
    local feature_version
    local package
    local dest_dir

    feature_version="$1"
    package="$2"

    dest_dir="${jdk_base_path}/temurin-${feature_version}.${package}"

    echo "$info Installing Temurin Java $feature_version ($package)..."
    if [ -d "$dest_dir" ]; then
        echo "$warning The destination directory '${dest_dir}' already exists on the system."
        echo 'If you proceed, I will need to delete the directory first.'
        if ! ask_user 'Do you want to continue?'; then
            echo 'Aborting!'
            return 1
        else
            sudo rm -rf "${dest_dir}" || return $?
        fi
    fi

    tar -C "${temp_unpack_dir}" -x -f "${temp_download_dir}/Temurin-${feature_version}.tgz" || return $?
    sudo mv "${temp_unpack_dir}"/* "$dest_dir" || return $?
    sudo chown -R root:wheel "${jdk_base_path}/temurin-${feature_version}.${package}" || return $?
}

install_temurin() {
    local feature_version
    local package # either 'jre' or jdk

    feature_version="$1"
    package="$2"

    if [ "$package" != 'jre' ] && [ "$package" != 'jdk' ]; then
        echo >&2 "$error Internal error! 'package' must be either 'jre' or 'jdk' but was: $package"
        exit 23
    fi

    while ! download_temurin "$feature_version" "$package"; do
        echo "$error Failed to download Temurin $(echo "$package" | tr '[:lower:]' '[:upper:]') ${feature_version}!"

        if ! ask_user 'Do you want to try again?'; then
            echo 'Giving up!'
            return 1
        fi 
    done

    while ! unpack_temurin "$feature_version" "$package"; do
        echo "$error Failed to extract Temurin binaries! (Have you mistyped your password?)"
        if ! ask_user 'Do you want to try again?'; then
            echo 'Giving up!'
            return 1
        fi
    done
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
    folder=${1##"${java_base_path}"/}
    folder=${folder%%/*}
    echo "$folder"
}

get_java_version() {
    local java_exe
    java_exe="$1"
    "$java_exe" -version 2>&1 | head -1 | cut -d ' ' -f 3 | tr -d '"'
}

get_java_feature_version() {
    local full_version
    local major
    local minor
    full_version=$1
    
    major=$(echo "$full_version" | cut -d '.' -f 1)
    minor=$(echo "$full_version" | cut -d '.' -f 2)

    if [ "$major" = '1' ]; then
        echo "$minor" # Should work for all Java versions < 11
    else
        echo "$major" # Should work for all Java versions >= 11
    fi
}

check_java_home() {
    local path
    path=$1
    if test -n "$JAVA_HOME" && starts_with "$JAVA_HOME" "$path"; then
        echo "$warning It seems that the environment variable JAVA_HOME is set and is pointing to:"
        echo "   JAVA_HOME=$JAVA_HOME"
        echo ''
        echo 'This is the installation location of the copy of Oracle Java that you asked me to remove.'
        echo "Updating JAVA_HOME is out of this script's scope."
        echo 'If you intend to proceed with the removal it is your responsibility to modify JAVA_HOME accordingly.'
        ask_user 'Do you still want to proceed with the removal?'
        return $?
    fi

    return 0
}

check_vintage() {
    local major
    major=$1

    if [ "$major" -lt 7 ]; then
        echo "Are you kidding me? Java 1.${major}? This version is old. Very, very, old..."
        echo 'In fact, it is so old that I do not know how to deal with it.'
        echo "Sorry, I can't help you. Bye!"
        exit 1
    elif [ "$major" -lt 8 ]; then
        echo_y 'Warning! Deprecated Java version!'
        echo "Java ${major} is no longer supported and Temurin does not provide builds for it!"
        echo 'Replacing it with Java 8 is likely a safe and sane option. That said, there is'
        echo 'a slim chance that some older Java applications will not run properly under Java 8.'
        echo ''
        if ask_user "Do you want to replace Java ${major} with Java 8?"; then
            true
        else
            false
        fi
    else
        true
    fi
}

# JRE related
install_temurin_jre() {
    install_temurin 8 jre
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

nuke_oracle_jre() {
    local rv
    rv=0
    if [ -d '/Library/Internet Plug-Ins/JavaAppletPlugin.plugin' ]; then
        echo "  ... removing '/Library/Internet Plug-Ins/JavaAppletPlugin.plugin' (you might need to enter your password)"
        sudo rm -rf '/Library/Internet Plug-Ins/JavaAppletPlugin.plugin' || { echo >&2 "$error: Failed to delete folder!"; rv=1; }
    fi

    if [ -d '/Library/PreferencePanes/JavaControlPanel.prefPane' ]; then
        echo "  ... removing '/Library/PreferencePanes/JavaControlPanel.prefPane' (you might need to enter your password)"
        sudo rm -rf '/Library/PreferencePanes/JavaControlPanel.prefPane' || { echo >&2 "$error: Failed to delete folder!"; rv=2; }
    fi

    if [ -d "$HOME/Library/Application Support/Oracle/Java" ]; then
        echo "  ... removing '$HOME/Library/Application Support/Oracle/Java'"
        rm -rf "$HOME/Library/Application Support/Oracle/Java" || { echo >&2 "$error: Failed to delete folder!"; rv=3; }
    fi

    # Sneaky bastards! Stop spying on me!
    if [ -d "$HOME/.oracle_jre_usage" ]; then
        echo "  ... removing '$HOME/.oracle_jre_usage'"
        rm -rf "$HOME/.oracle_jre_usage" || { echo >&2 "$error: Failed to delete folder!"; rv=4; }
    fi

    return $rv
}

jre_info() {
    echo 'Oracle JRE! It sucks! Supports Java Applets (dead) and Java Web Start though.'
    echo 'Temurin JRE is not a 1:1 replacement, but you can combine it with Open Web Start'
    echo '(https://openwebstart.com/) to provide most of the functionality'
}

deal_with_jre() {
    local jre_bin
    local full_version
    local feature_version

    echo -n '‣ Checking if Oracle JRE is installed...'
    jre_bin="$(has_oracle_jre)"

    if [ -n "$jre_bin" ]; then
        full_version=$(get_java_version "$jre_bin")
        feature_version=$(get_java_feature_version "$full_version")
        echo_y "found Oracle JRE ${feature_version} (${full_version})!"
        jre_info

        if ask_user 'Do you want to replace Oracle JRE with Temurin JRE?'; then
            echo "Alright! Let's do this!"
            if ! check_vintage "$feature_version"; then
                echo "Fine. I won't change anything!"
                return
            fi

            if ! has_temurin_jre; then
                install_temurin_jre
            else
                echo 'Looks like Temurin 8 JRE is already installed on this system.'
            fi

            if check_java_home "$jre_bin"; then
                echo 'Removing Oracle JRE...'
                if nuke_oracle_jre; then
                    echo 'Oracle JRE removed!'
                else
                    echo "$warning It seems that I could not fully remove Oracle JRE!"
                fi
            fi
        else
            echo 'Fine! I will leave everything as is.'
        fi
    else
        echo_g 'no!'
        echo -n '‣ Checking if remnants of a previous JRE installation are still around...'
        if has_oracle_jre_remnants; then
            echo_y 'found!'
            echo 'I found some remnants from a previous installation of Oracle JRE that can be safely deleted.'
            if ask_user 'Do you want me to remove them?'; then
                echo 'Okay! Will do!'
                if nuke_oracle_jre; then
                    echo 'Remnants removed!'
                else
                    echo "$warning It seems that not all remnants could be removed!"
                fi
            else
                echo "Fine! I won't touch anything!"
            fi
        else
            echo_g 'no!'
        fi
    fi
}
# end JRE related

# JDK related
nuke_oracle_jdk() {
    local java_folder
    java_folder=$(get_java_folder "$1")

    pushd "$jdk_base_path" 1> /dev/null || { echo >&2 "$error Failed to change working directory!"; exit 1; }
    sudo ls -ld "$java_folder" # TODO: Replace with rm -rf
    popd 1> /dev/null || { echo >&2 "$error Failed to return to previous working directory!"; exit 1; }
}

deal_with_jdks() {
    local oracle_jdks
    local openjdk_jdks
    oracle_jdks=()
    openjdk_jdks=()
    
    echo -n '‣ Checking if Oracle JDKs are installed...'
    while IFS='' read -r line; do test -n "$line" && oracle_jdks+=("$line"); done < <(discover_java_exes 'oracle' 'jdk')
    while IFS='' read -r line; do test -n "$line" && openjdk_jdks+=("$line"); done < <(discover_java_exes 'openjdk' 'jdk')

    if [ ${#oracle_jdks[@]} -gt 0 ]; then
        echo_y 'found some!'
        
        for oj in "${oracle_jdks[@]}"; do
            full_ver=$(get_java_version "$oj")
            major_ver=$(get_java_feature_version "$full_ver")
            echo "  • Oracle Java $major_ver ($full_ver) at $oj"
        done
    else
        echo_g 'no!'
    fi

    echo -n '‣ Checking if OpenJDK JDKs are installed...'
    if [ ${#openjdk_jdks[@]} -gt 0 ]; then
        echo_g "found some!"
        for oj in "${openjdk_jdks[@]}"; do
            full_ver=$(get_java_version "$oj")
            major_ver=$(get_java_feature_version "$full_ver")
            echo "  • OpenJDK Java $major_ver ($full_ver) at $oj"
        done
    else
        echo_y 'no!'
    fi


}
# end JDK related


deal_with_jre
deal_with_jdks
#discover_java_exes 'oracle' 'jdk'

