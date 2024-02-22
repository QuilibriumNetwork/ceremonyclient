# Quilibrium Docker Instructions

## Build

Build the docker image:
```shell
docker build -t quilibrium -t quilibrium:1.2.9 .
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

