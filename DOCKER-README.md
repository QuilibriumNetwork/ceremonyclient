# Quilibrium Docker Instructions

## WARNING

> [!WARNING]
> Currently Docker cannot be used to run Quilibrium.

There are extreme buffering requirements, especially during sync, and these in turn require `sysctl`
configuration changes that unfortunately are not supported by Docker.

The buffer related `sysctl` settings are `net.core.rmem_max` and `net.core.wmem_max` and they both
should be set to `600,000,000` bytes. This value allows pre-buffering of the entire maximum payload
for sync.

To read the currently set values:
```shell
sysctl -n net.core.rmem_max
sysctl -n net.core.wmem_max
```

To set new values:
```shell
sudo sysctl -w net.core.rmem_max=600000000
sudo sysctl -w net.core.wmem_max=600000000
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


## Intereact with a running cotainer

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

Get the token ballance:
```shell
docker compose exec node go run ./... -balance
```

Run the DB console:
```shell
docker compose exec node go run ./... -db-console
```

