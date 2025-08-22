# story-loglume



## Requirements

* Two servers running **Ubuntu 20.04+** (or later):

  * **Server A**: Elasticsearch + Kibana
  * **Server B**: Fluent Bit (and Story node)
* SSH access to both servers.
* UFW (Uncomplicated Firewall) installed on each server (optional, for managing network ports).

> **Tip:** Run all commands below with `sudo` (root privileges).

## Port check & opening

1. **Check if required ports are listening (9200, 5601, 2020):**

   ```bash
   sudo ss -tuln | grep -E "9200|5601|2020"
   ```

   At this initial stage, none of these services are running yet, so it’s expected that no output is returned.

2. **Open necessary ports in the firewall (UFW):**

   ```bash
   sudo ufw allow 9200/tcp   # Elasticsearch HTTP API  
   sudo ufw allow 5601/tcp   # Kibana Web UI  
   sudo ufw allow 2020/tcp   # Fluent Bit HTTP metrics  
   sudo ufw reload
   ```

   This ensures external access to Elasticsearch (9200), Kibana (5601), and Fluent Bit’s metrics endpoint (2020).

3. **Verify firewall rules:**

   ```bash
   sudo ufw status
   ```

   You should see allow rules for **9200**, **5601**, and **2020** (if UFW is active).

## Preparing servers

1. **SSH into Server A (Elasticsearch/Kibana server):**

   ```bash
   ssh root@<IP_Server_A>
   ```

2. **SSH into Server B (Fluent Bit & Story server):**

   ```bash
   ssh root@<IP_Server_B>
   ```

3. **Update package lists and upgrade on both servers:**

   ```bash
   apt update && apt upgrade -y
   ```

   This ensures all system packages are up-to-date before installing the EFK components.

