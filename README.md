# Flare
Simple reverse proxy server

## Notice
- ⚠️ Not recommended to use in large-scale infrastructures.

## How to setup
- Remove `.example` from `config.yaml.example` and setup your routes
- Run the executable

### If giving permission denied on port :80
- `sudo setcap 'CAP_NET_BIND_SERVICE+ep' ./flare`