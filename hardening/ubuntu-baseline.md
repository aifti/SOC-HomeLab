This is going to be our baseline for what our Ubuntu Server (Wazuh Server) will be set with so that way we protect our server from unauthorized access.

- 1st step: System updates + patches
            ex) sudo apt update && sudo apt upgrade -y
                enable automatic security updates if possible

- 2nd step: Firewall (UFW)
            ex) Default: deny incoming traffic (TCP, UDP, SSH) unless specified IPs listed, allow outgoing
                Allow SSH (port 22) only from our IP address
                **I managed these settings within DigitalOcean since our Wazuh Server is hosted on the cloud, however it is possible to enable this via CLI once the server is up**
  

- 3rd step: SSH hardening
            ex) Disable root logins
                Disable password authentication (ideally use ssh key) **In my case I used password auth since this is a small project but for real life purpose ideally use ssh key**

- 4th step: Accounts + Sudo
            ex) Use non-root account

- 5th step: Intrusion prevention/monitoring
            ex) Log monitoring with our Wazuh Dashboard

