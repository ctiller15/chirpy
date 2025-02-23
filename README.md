# chirpy

## setup
```bash
#install postgres

# macos
brew install postgresql@15

# linux
sudo apt update
sudo apt install postgresql postgresql-contrib

# enter psql shell
# mac
psql postgres

# linux
sudo -u postgres psql

# create db
CREATE DATABASE chirpy;
```

## Running goose migrations
```bash
# macos export env var
$DATABASE_CONNECTION_STRING="..."

# up
cd sql/schema && goose postgres $DATABASE_CONNECTION_STRING up && cd ../..

# down
cd sql/schema && goose postgres $DATABASE_CONNECTION_STRING down && cd ../..
# down
```

## Using sqlc
```bash
# installing
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

## build and run
```bash
go build -o out && ./out
```

## API Resources