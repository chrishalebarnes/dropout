Dropout
=======
[Dropout](https://github.com/chrishalebarnes/dropout) is a collection of [bash](https://en.wikipedia.org/wiki/Bash_%28Unix_shell%29) functions wrapped around [iptables](https://en.wikipedia.org/wiki/Iptables). These functions serve as documentation, ideas, and a set of building blocks to create a script that configures `iptables` on a server.

All of the functions are contained in [source.sh](https://github.com/chrishalebarnes/dropout/blob/master/source.sh). Browse around that file for an idea of what's in there.

## Using Dropout
Obviously it's up to your needs to figure out what you need. Here's an example of a fairly strict script. For example, this will not even allow outgoing traffic to non approved ip addresses. Don't forget after creating the script to make it executable `chmod u+x myscript.sh` (this command needs `sudo`). Here's a fairly typical example allowing connections between a web server and a database server. These rules will not let `git` through, so get the `source.sh` file to your server however you see fit.

```
#!/bin/bash

source "path/to/dropout/source.sh"

db="xx.xxx.x.xx"   # database server ip address
web="xx.xxx.x.xx"  # web server ip address
private_web="eth1" # private interface for web server
public_web="eth0"  # public interface for web server
private_db="eth1"  # private interface for database server

web() {
  echo "Setting up iptables for a web server"
  wipe_iptables
  blacklist "xx.xxx.x.xx"  # space separated blacklist of known bad IPs to drop
  disallow_spam_ips "/etc/ssl/certs/ca-certificates.crt" # disallows the spamhaus IP drop list, uses curl and https provide a certificate path
  allow_mail 465 # allow SMTP over port
  allow_http $public_web 80 # allow http over port
  allow_https $public_web 443 # allow https over port
  allow_to_and_from_over_port $private_web $db $web 3306 # database private interface <=> web server private interface
  allow_pings
  allow_ssh 22 # Specify ssh port. Consider changing it away from port 22
  allow_loopback # allow localhost
  allow_dns
  allow_apt_get
  allow_established_connections
  allow_from_and_to $web $db  # database <=> web server
  drop_the_rest
  print_current_tables
  echo "Done."
}

database () {
  echo "Setting up iptables for a database server"
  allow_to_and_from_over_port $private_db $web $db 3306 # database server <=> web server
  allow_pings
  allow_ssh 22
  allow_loopback
  allow_dns
  allow_established_connections
  drop_the_rest
  print_current_tables
  echo "Done."
}

server="$1"

if [ "$server" == "db" ]; then
  database
elif [ "$server" == "web" ]; then
  web
elif [ "$server" == "clear" ]; then
  wipe_iptables
else
  echo "Error: no parameter supplied"
  exit 1
fi
```

Then you can set up `iptables` likes this `./path/to/script.sh web` or `./path/to/script.sh db`


## License and Copyright

See [LICENSE](https://github.com/chrishalebarnes/dropout/blob/master/LICENSE)
