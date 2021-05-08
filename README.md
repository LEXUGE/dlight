# dlight
A DNS tunnel proxy tool using QUIC

# Usage
Server:
```
dlight --bind "ADDRESS"
```
Client
```
dlight --bind "SOCKS5 ADDRESS TO LISTEN" --remote "SERVER BOUND ADDRESS"
```
