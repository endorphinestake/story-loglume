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


## Installing Elasticsearch & Kibana on Server A

Server A will host the logging backend: **Elasticsearch** for storage/search and **Kibana** for visualization.

### Step 1. Install Java (OpenJDK 11)

Elasticsearch requires Java. Install OpenJDK 11:

```bash
apt install -y openjdk-11-jdk
java -version    # should output version 11
```

### Step 2. Install Elasticsearch

Add Elastic’s official 7.x APT repository and install Elasticsearch:

```bash
# Import Elasticsearch GPG key and repository
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] \
  https://artifacts.elastic.co/packages/7.x/apt stable main" \
  > /etc/apt/sources.list.d/elastic-7.x.list

apt update
apt install -y elasticsearch

# Enable and start the Elasticsearch service
systemctl enable elasticsearch
systemctl start elasticsearch
```

### Step 3. Configure Elasticsearch

By default Elasticsearch binds to localhost and has no security enabled. Adjust the config for our setup:

```bash
# Create config file (if not already present) and set parameters
mkdir -p /etc/elasticsearch
tee /etc/elasticsearch/elasticsearch.yml > /dev/null <<EOF
network.host: 0.0.0.0                  # listen on all interfaces
discovery.type: single-node            # single node cluster
xpack.security.enabled: true          # enable security (authentication)
xpack.security.authc.api_key.enabled: true  # enable API key auth
EOF

# Restart Elasticsearch to apply config
systemctl restart elasticsearch
```

If you encounter permissions issues on first startup (Elasticsearch may need specific directories):

```bash
mkdir -p /usr/share/elasticsearch/{logs,data}
chown -R elasticsearch:elasticsearch /usr/share/elasticsearch/logs
chown -R elasticsearch:elasticsearch /usr/share/elasticsearch/data
systemctl restart elasticsearch
systemctl status elasticsearch   
# ensure it is active/running
```

### Step 4. Install Kibana

Install Kibana from the Elastic repository:

```bash
apt update
apt install -y kibana

# Enable and start Kibana service
systemctl enable kibana
systemctl start kibana
```

### Step 5. Configure Kibana

Allow Kibana to be accessible remotely and point it to local Elasticsearch:

```bash
mkdir -p /etc/kibana
tee /etc/kibana/kibana.yml > /dev/null <<EOF
server.host: "0.0.0.0"                   # listen on all interfaces
elasticsearch.hosts: ["http://127.0.0.1:9200"]
elasticsearch.ssl.verificationMode: none  # disable SSL verification (if using HTTP)
EOF

systemctl restart kibana
```

Kibana will now be accessible via **http\://\<IP\_Server\_A>:5601**.

## Retrieving password & API key on Server A

With security enabled, Elasticsearch creates a default `elastic` superuser. We need to set its password and generate an API key for Fluent Bit to ingest logs.

### Step 6. Set the `elastic` user password

Run the interactive setup to define passwords for built-in users:

```bash
/usr/share/elasticsearch/bin/elasticsearch-setup-passwords interactive
```

Choose “Yes” when prompted, then set passwords for all users. Be sure to **note the `elastic` password** for later.

### Step 7. Generate an API key for Fluent Bit

We will use an API key (with `monitoring` privileges) for Fluent Bit to send data to Elasticsearch:

```bash
curl -u "elastic:<ELASTIC_PASS>" -X POST "http://127.0.0.1:9200/_security/api_key" \
  -H 'Content-Type: application/json' \
  -d '{ "name": "fluent-bit", "expiration": "90d" }'
```

The JSON response will contain an `id` and `api_key`. **Save these values.** (Alternatively, Fluent Bit can authenticate using the `elastic` username and password, but an API key is more secure to use in config.)

## Installing Fluent Bit on Server B

Server B will run **Fluent Bit** to read Story node logs (from systemd journal) and forward them to Elasticsearch on Server A.

### Step 8. Install Fluent Bit

Remove any old versions of Fluent Bit and install the latest version:

```bash
# Purge old installations if present
apt purge -y fluent-bit
rm -rf /etc/fluent-bit /opt/fluent-bit /var/log/fluent-bit

# Install latest Fluent Bit (official script)
curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh

# Create a convenient symlink to the binary
ln -sf /opt/fluent-bit/bin/fluent-bit /usr/local/bin/fluent-bit

# Verify installation
fluent-bit --version
```


