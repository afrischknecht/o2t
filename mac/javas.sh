#!/bin/bash

# Discover Java versions installed on MacOS and opts to replace Oracle Java with Temurin.
java_base_path=/Library/Java/JavaVirtualMachines
adoptium_api=https://api.adoptium.net
temp_download_dir=$(mktemp -d)
temp_unpack_dir="$temp_download_dir/temurin"

oracle_major=()
openjdk_major=()

cleanup() {
    rm -rf $temp_download_dir
}
trap cleanup EXIT

discover_javas() {
    local flavor=$1 #either 'oracle' or 'openjdk'
    local versions
    local exec_cmd
    if [ $flavor = 'oracle' ]; then
        exec_cmd='JBIN={}; $JBIN -version 2>&1 | grep -q "^Java(TM)" && echo $JBIN'
    else
        exec_cmd='JBIN={}; $JBIN -version 2>&1 | grep -q "^OpenJDK Runtime" && echo $JBIN'
    fi
    versions=$(find $java_base_path -type f -name java -exec bash -c "$exec_cmd" \;)
    echo $versions
}

get_java_version() {
    local java_exe=$1
    $java_exe -version 2>&1 | head -1 | cut -d ' ' -f 3 | tr -d '"'
}

get_java_feature_version() {
    local full_version
    local major
    local minor
    full_version=$1
    major=$(echo $full_version | cut -d '.' -f 1)
    minor=$(echo $full_version | cut -d '.' -f 2)

    if [ $major = '1' ]; then
        echo $minor # Should work for all Java versions < 11
    else
        echo $major # Should work for all Java versions >= 11
    fi
}

discover_oracle_javas() {
    discover_javas 'oracle'
}

discover_openjdk_javas() {
    discover_javas 'openjdk'
}

get_architecture() {
    local arch
    arch=$(uname -m)
    if [ $arch = 'x86_64' ]; then # Intel
        echo 'x64'
    elif [ $arch = 'arm64' ]; then # Apple Silicon
        echo 'aarch64'
    else
        echo >&2 "Unsupported processor architecture: $arch"
        exit 1
    fi
}

install_temurin() {
    local feature_version=$1
    local url
    local status_code
    url="${adoptium_api}/v3/binary/latest/${feature_version}/ga/mac/$(get_architecture)/jdk/hotspot/normal/eclipse"
    status_code=$(curl -s -w '%{http_code}' $url)
    if [ $status_code != '307' ]; then
        echo "[ERROR] Failed to get download URL for Temurin Java $feature_version!"
        exit 1
    fi
    echo "[INFO] Downloading Temurin Java $feature_version..."
    curl -# -L -o "${temp_download_dir}/Temurin-${feature_version}.tgz" $url

    echo "[INFO] Installing Temurin Java $feature_version..."
    tar -C ${temp_unpack_dir} -x -f "${temp_download_dir}/Temurin-${feature_version}.tgz"
    sudo mv ${temp_unpack_dir}/* ${java_base_path}/temurin-${feature_version}.jdk
    sudo chown -R root:wheel ${java_base_path}/temurin-${feature_version}.jdk
}

get_java_folder() {
    local folder
    folder=${1##${java_base_path}/}
    folder=${folder%%/*}
    echo $folder
}

nuke_oracle_java() {
    local java_folder
    java_folder=$(get_java_folder $1)

    pushd $java_base_path 1> /dev/null
    sudo ls -ld $java_folder # TODO: Replace with rm -rf
    popd 1> /dev/null
}

ask_user() {
    local answer
    local question
    question=$1

    while [ -z $answer ]; do
        echo "$question [y/n]"
        read -s -n 1 answer
        if [[ $answer != 'y' && $answer != 'n' ]]; then
            echo "Please answer with either 'y' or 'n'!"
            answer=
        fi
    done

    if [ $answer = 'y' ]; then
        return 0
    fi

    return 1
}

remove_or_replace_oracle() {
    local feature_version
    local full_version
    local oracle_java
    oracle_java=$1

    full_version=$(get_java_version $oracle_java)
    feature_version=$(get_java_feature_version $full_version)

    if [ $feature_version < 8 ]; then
        echo "TODO"
    fi

    local oj_exists
    oj_exists='no'
    for j in in ${openjdk_major[@]}; do
        test $j = $feature_version && oj_exists='yes'
    done

    if [ $oj_exists = 'yes' ]; then
        echo "It seems that an OpenJDK for Java ${feature_version} is already installed on the system."
        echo "I am just going to remove Oracle Java ${feature version}."
    else
        echo "It seems that no OpenJDK for Java ${feature_version} is installed."
        echo 'I am going to install a corresponding release of Temurin OpenJDK.'
        install_temurin $feature_version
    fi

    nuke_oracle_java $oracle_java
}

main() {
    local oracle_javas
    local openjdk_javas
    
    local major_ver
    local full_ver

    mkdir -p $temp_unpack_dir

    oracle_javas=( $(discover_oracle_javas) )
    openjdk_javas=( $(discover_openjdk_javas) )

    if [ ${#oracle_javas[@]} -gt 0 ]; then
        echo 'Found the following Oracle Javas on the system:' 
        for oj in ${oracle_javas[@]}; do
            full_ver=$(get_java_version $oj)
            major_ver=$(get_java_feature_version $full_ver)
            echo "  Oracle Java $major_ver ($full_ver)"
            oracle_major+=( $major_ver )
        done
    else
        echo 'No Oracle Java found on the system!'
    fi

    if [ ${#openjdk_javas[@]} -gt 0 ]; then
        echo 'Found the following OpenJDK Javas on the system:' 
        for oj in ${openjdk_javas[@]}; do
            full_ver=$(get_java_version $oj)
            major_ver=$(get_java_feature_version $full_ver)
            echo "  OpenJDK Java $major_ver ($full_ver)"
        done
    else
        echo 'No OpenJDK Java found on the system!'
    fi

    if [ ${#oracle_javas[@]} -eq 0 ]; then
        local rv
        ask_user 'Do you want to replace all Oracle Java installations with Temurin OpenJDK?'
        rv=$?

        if [ $rv -eq 0 ]; then
            echo 'Good choice!'
        else
            echo 'Pity! Oh, well...'
        fi
    fi
}

main