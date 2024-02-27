# Quilibrium Docker Instructions

## WARNING

> [!WARNING]
> The Quilibrium docker container requires host configuration changes.

There are extreme buffering requirements, especially during sync, and these in turn require `sysctl`
configuration changes that unfortunately are not supported by Docker. But if these changes are made on
the host machine, then luckily containers seem to automatically have the larger buffers.

The buffer related `sysctl` settings are `net.core.rmem_max` and `net.core.wmem_max` and they both
should be set to `600,000,000` bytes. This value allows pre-buffering of the entire maximum payload
for sync.

You can tell that the buffer size is not large enough by noticing this log entry at beginning when 
Quilibrium starts, a few lines below the large logo:
> failed to sufficiently increase receive buffer size (was: 208 kiB, wanted: 2048 kiB, got: 416 kiB).
> See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details.

To read the currently set values:
```shell
sysctl -n net.core.rmem_max
sysctl -n net.core.wmem_max
```

To set new values, this is not a persistent change:
```shell
sudo sysctl -w net.core.rmem_max=600000000
sudo sysctl -w net.core.wmem_max=600000000
```

To persistently set the new values add a configuration file named `20-quilibrium.conf` to
`/etc/sysctl.d/`. The file content should be:
```
# Quilibrium buffering requirements, especially during sync.
# The value could be as low as 26214400, but everything would be slower.

net.core.rmem_max = 600000000
net.core.wmem_max = 600000000
```

## Build

Build the docker image:
```shell
docker build --build-arg GIT_COMMIT=$(git log -1 --format=%h) -t quilibrium -t quilibrium:1.2.9 .
```

Use latest version instead of `1.2.9`.


## Run

Run Quilibrium in a container:
```shell
docker compose up -d
```

A `.config/` subfolder will be created under the current folder, this is mapped inside the container.
Make sure you backup `config.yml` and `keys.yml`.


## Interact with a running container

Drop into a shell inside a running container:
```shell
docker compose exec -it node sh
```

Watch the logs:
```shell
docker compose logs
```

Get the Peer ID:
```shell
docker compose exec node go run ./... -peer-id
```

Get the token balance:
```shell
docker compose exec node go run ./... -balance
```

Run the DB console:
```shell
docker compose exec node go run ./... -db-console
```

