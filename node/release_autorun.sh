#!/bin/bash

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    release_os="linux"
    if [[ $(uname -m) == "aarch64"* ]]; then
        release_arch="arm64"
    else
        release_arch="amd64"
    fi
else
    release_os="darwin"
    release_arch="arm64"
fi

start_process() {
    chmod +x ./node-$version-$release_os-$release_arch
    ./node-$version-$release_os-$release_arch &
    main_process_id=$!
    echo "process started with PID $main_process_id"
}

is_process_running() {
    ps -p $main_process_id > /dev/null 2>&1
    return $?
}

kill_process() {
    local process_count=$(ps -ef | grep -E "node-.*-(darwin|linux)-(amd64|arm64)" | grep -v grep | wc -l)
    local process_pids=$(ps -ef | grep -E "node-.*-(darwin|linux)-(amd64|arm64)" | grep -v grep | awk '{print $2}' | xargs)

    if [ $process_count -gt 0 ]; then
        echo "killing processes $process_pids"
        kill $process_pids
    else
        echo "no processes running"
    fi
}

fetch() {
    files=$(curl https://releases.quilibrium.com/release | grep $release_os-$release_arch)
    new_release=false

    for file in $files; do
        version=$(echo "$file" | cut -d '-' -f 2)
        if ! test -f "./$file"; then
            curl "https://releases.quilibrium.com/$file" > "$file"
            new_release=true
        fi
    done
    echo $new_release
}

git_update_manager() {
    while true; do
        new_release=$(fetch)
        git fetch
        local_head=$(git rev-parse HEAD)
        remote_head=$(git rev-parse @{u})

        if [ "$new_release" == "true" ] || [ "$local_head" != "$remote_head" ]; then
            updating=true
            kill_process
            if [ "$local_head" != "$remote_head" ]; then
                git pull
            fi
            start_process
            updating=false
        fi

        sleep 43200
    done
}

crash_detector() {
    while true; do
        if ! is_process_running && [ "$updating" != true ]; then
            echo "process crashed or stopped. restarting..."
            start_process
        fi

        sleep 300
    done
}

# Initialize updating flag
updating=false

new_release=$(fetch)
kill_process
start_process

# Run git_update_manager and crash_detector in parallel
git_update_manager &
crash_detector &
wait
