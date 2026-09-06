# Blucifer - Bluetooth Reconnaissance Multi-Tool

Blucifer tracks Bluetooth devices in your vicinity and allows you to develop patterns of life based on these devices.

---

> **WARNING: Extremely Alpha Software**
>
> Blucifer is in the very early stages of development. At this point, it's an experimental prototype more than anything. Things may change or break without warning.

---

# Quick Start

**Note:** While this project will run on macOS, it is more limited. It is recommended that you run this on Linux for best results.

Blucifer runs as **two independent services** that talk over HTTP:

- **`blucifer web`** — the dashboard, database, and ingest API. This is the system
  of record; only this node needs the SQLite database.
- **`blucifer scan`** — a Bluetooth sensor. It scans and pushes observations to a
  web node. It keeps no database, only a small local store-and-forward spool so a
  UI outage never drops data.

Install only what a node needs — `blucifer[web]`, `blucifer[sensor]`, or
`blucifer[all]` for both on one host:

```bash
pip install -e ".[all]"          # local: run both services here
pip install -e ".[web]"          # dashboard-only host
pip install -e ".[sensor]"       # sensor-only host (e.g. a Raspberry Pi)
```

Run both on one machine:

```bash
blucifer web                                   # terminal 1  (http://127.0.0.1:8080)
blucifer scan --server-url http://127.0.0.1:8080   # terminal 2
```

Or split them across boxes (sensor on a Pi, dashboard on a server). Set a shared
secret so the sensor can authenticate to the web node:

```bash
# on the web host
blucifer web --host 0.0.0.0 --ingest-token "$(openssl rand -hex 16)"

# on each sensor host — name it so you can tell rooms apart in the UI
blucifer scan --server-url http://ui-host:8080 --ingest-token <same-token> \
              --sensor-name living-room
```

## Configuration

Blucifer exposes a number of environment variables that allow you to override the defaults. The following configuration environment variables are available:

| Variable                 | Description                                         | Default Value          |
|--------------------------|-----------------------------------------------------|------------------------|
| `BLUCIFER_DATA_DIR`      | The directory where Blucifer stores all of its data | `~/.local/share/blucifer/` |
| `BLUCIFER_DB_PATH`       | The path at which Blucifer stores its database      | `$BLUCIFER_DATA_DIR/blucifer.db` |
| `BLUCIFER_WEB_HOST`      | The host string for the Blucifer web UI             | `127.0.0.1`            |
| `BLUCIFER_WEB_PORT`      | The port on which the web interface runs            | `8080`                 |
| `BLUCIFER_SIGHTINGS_RETENTION_DAYS` | The number of days to retain sighting information (can be overridden in the web interface) | `30` |
| `BLUCIFER_VISIT_GAP_SECONDS` | Seed default for the visit idle-gap, in seconds: a new "visit" (presence session) on a device's page starts after a sighting gap longer than this (can be overridden in the web interface) | `900` |
| `BLUCIFER_SENSOR_NAME`   | The name of the sensor to show in the UI            | The sensor's hostname |
| `BLUCIFER_SERVER_URL`   | The URL for the Blucifer server that the sensor sends observations to. | None |
| `BLUCIFER_INGEST_TOKEN`  | Shared secret for POST requests to the server. | None |
| `BLUCIFER_SPOOL_PATH` | The on-disk queue for unsent scan results that need to be sent to the server. | `$BLUCIFER_DATA_DIR/spool.db` |
| `BLUCIFER_SPOOL_MAX_BATCHES` | The max number of batches to use for the on-disk spool queue. | `5000` |
| `BLUCIFER_ADAPTER` | The adapter to use for BLE scanning. | None |
| `BLUCIFER_CLASSIC_ADAPTER` | The adapter to use for classic Bluetooth scanning. | None |

# Credits

- This project was originally heavily inspired by [Bluehood](https://github.com/dannymcc/bluehood). While originally based on the wonderful work of this project, Blucifer is completely unique and separate from the Bluehood project.
- The name and design language are an homage to the [Blucifer Statue](https://en.wikipedia.org/wiki/Blue_Mustang) outside the Denver International Airport.

# License

Blucifer is licensed under the MIT License. See [LICENSE](LICENSE) for details.

# Disclaimer

Blucifer is built for educational and research purposes only. You're responsible for being mindful of any privacy laws in your area when monitoring Bluetooth devices. The author(s) of this project are in now way responsible for your misuse of this software.

---

Blucifer is created by [Adam Thompson](https://hackeradam.com).