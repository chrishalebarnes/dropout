#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
RESET='\033[0m'

# Note: iptables are ordered, drop_the_rest must be last
function drop_the_rest() {
  sudo iptables -A INPUT   -j DROP
  sudo iptables -A OUTPUT  -j DROP
  sudo iptables -A FORWARD -j DROP
  echo -e "${GREEN}Drop everything else!${RESET}"
}

function disallow_blacklist_ips() {
  local blocklist="$1"

  if [ ! -z $blocklist ]; then
    for ip in $blocklist ; do
      sudo iptables -A INPUT -s $ip -j DROP
    done
    echo -e "${GREEN}Blaclist blocked.${RESET}"
  else
    echo -e "${RED}Ignoring ssh since ssh port not provided.${RESET}"
  fi
}

function disallow_spam_ips() {
  local cert_location="$1"

  if [ ! -z $cert_location ]; then
    # first allow https connections to spamhaus.org
    sudo iptables -A OUTPUT -p tcp -d www.spamhaus.org --dport 443 -j ACCEPT

    # download the drop list and grab the IPs and drop them
    for ip in $(curl --cacert $cert_location https://www.spamhaus.org/drop/drop.txt | grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:\/\d+)?'); do
      sudo iptables -A INPUT -s $ip -j DROP
    done
    echo -e "${GREEN}Spam IPS blocked.${RESET}"
  else
    echo -e "${RED}Ignoring spam blocking since a certificate location is not provided. For example, on Debian based systems, the system certificates are located at /etc/ssl/certs/ca-certificates.crt${RESET}"
  fi
}

function wipe_iptables() {
  sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  sudo iptables -F
  sudo iptables -X
  sudo iptables -t nat -F
  echo -e "${GREEN}iptables cleared.${RESET}"
}

function allow_mail() {
  local port="$1"

  if [ ! -z $port ]; then
    sudo iptables -A OUTPUT -p tcp --sport $port -m state --state NEW,ESTABLISHED -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --dport $port -m state --state NEW,ESTABLISHED -j ACCEPT
    sudo iptables -A INPUT  -p tcp --sport $port -m state --state RELATED,ESTABLISHED  -j ACCEPT
    echo -e "${GREEN}Allowed mail on port ${port}.${RESET}"
  else
    echo -e "${RED}Ignoring mail since a port was not provided${RESET}"
  fi
}

function allow_http() {
  local interface="$1"
  local port="$2"

  if [ ! -z $interface ] && [ ! -z $port ]; then
    sudo iptables -A INPUT  -i $interface -p tcp --dport $port  -m state --state NEW -j ACCEPT
    sudo iptables -A OUTPUT -o $interface -p tcp --sport $port                       -j ACCEPT
    echo -e "${GREEN}Allowed HTTP on port ${port}.${RESET}"
  else
    echo -e "${RED}Ignoring HTTP since an interface or port was not provided"
  fi
}

function allow_https() {
  local interface="$1"
  local port="$2"

  if [ ! -z $interface ] && [ ! -z $port ]; then
    sudo iptables -A INPUT  -i $interface -p tcp --dport $port -m state --state NEW -j ACCEPT
    sudo iptables -A OUTPUT -o $interface -p tcp --sport $port                      -j ACCEPT
    echo -e "${GREEN}Allowed HTTPS on port ${port}.${RESET}"
  else
    echo -e "${RED}Ignoring HTTPS since an interface or port was not provided${RESET}"
  fi
}

function allow_apt_get() {
  sudo iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
  sudo iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW -j ACCEPT
  sudo iptables -A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
  echo -e "${GREEN}Allowed apt-get.${RESET}"
}

function allow_pings() {
  sudo iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
  sudo iptables -A INPUT  -p icmp --icmp-type echo-request -j ACCEPT
  sudo iptables -A INPUT  -p icmp --icmp-type echo-reply   -j ACCEPT
  sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply   -j ACCEPT
  echo -e "${GREEN}Allowed pings.${RESET}"
}

function allow_loopback() {
  sudo iptables -A INPUT  -i lo -j ACCEPT
  sudo iptables -A OUTPUT -o lo -j ACCEPT
  echo -e "${GREEN}Allowed loopback.${RESET}"
}

function allow_ssh() {
  local port="$1"
  if [ ! -z $port ]; then
    sudo iptables -A INPUT  -p tcp --dport $port -m state --state NEW  -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --sport $port                       -j ACCEPT
    echo -e "${GREEN}Allowed ssh on port ${port}.${RESET}"
  else
    echo -e "${RED}Ignorning ssh since ssh port not provided.${RESET}"
  fi
}

function allow_dns() {
  sudo iptables -A INPUT  -p udp -m udp --sport 53 -j ACCEPT
  sudo iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
  echo -e "${GREEN}Allowed DNS.${RESET}"
}

function print_current_tables() {
  sudo iptables -L -v -n
}

function allow_established_connections() {
  sudo iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
  sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  echo -e "${GREEN}Allowed established connections.${RESET}"
}

function allow_sendmail() {
  sudo iptables -A INPUT  -p tcp -i localhost --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
  sudo iptables -A OUTPUT -p tcp --sport 25 -m state --state ESTABLISHED     -j ACCEPT
  echo -e "${GREEN}Allowed sendmail on port 25.${RESET}"
}

function allow_from_and_to() {
  local from="$1"
  local to="$2"

  if [ ! -z $from ] && [ ! -z $to ]; then
    sudo iptables -A OUTPUT -s $from -d $to -m state --state NEW -j ACCEPT
    echo -e "${GREEN}Allowed from ${from} to ${to}.${RESET}"
  else
    echo -e "${RED}Ignoring allow_from_and_to since from or two is not defined${RESET}"
  fi
}

function allow_to_and_from_over_port() {
  local interface="$1"
  local from="$2"
  local to="$3"
  local port="$4"

  if [ ! -z $interface ] && [ ! -z $from ] && [ ! -z $to ] && [ ! -z $port ]; then
    sudo iptables -A INPUT  -i $interface -s $from -d $to   -p tcp -m tcp --dport $port -m state --state NEW -j ACCEPT
    sudo iptables -A OUTPUT -o $interface -s $to   -d $from -p tcp -m tcp --sport $port -m state --state NEW -j ACCEPT
    sudo iptables -A INPUT  -i $interface -s $from -d $to   -p udp -m udp --dport $port -m state --state NEW -j ACCEPT
    sudo iptables -A OUTPUT -o $interface -s $to   -d $from -p udp -m udp --sport $port -m state --state NEW -j ACCEPT
    echo -e "${GREEN}Allowed from ${from} to ${to} over port ${port}.${RESET}"
  else
    echo -e "${RED}Ignoring allow_to_and_from_over_port because some of the parameters are not defined${RESET}"
  fi
}
