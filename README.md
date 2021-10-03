# zoidbergstrike 👀
A tool to hunt/mine for Cobalt Strike beacons and "reduce"
their beacon configuration for later indexing. Hunts can either be expansive and internet wide using services like SecurityTrails, Shodan, or ZoomEye or a list of IP's.

![](static/logo.png)

## Getting started

1. [Install](#installation) ZoidbergStrike
2. [Configure](#configuration) your tokens to begin the hunt
3. [Mine](#search-examples) Beacons to begin reducing them
4. Review results `cat results.json | jq`

:tv: **Demo**

![](static/demo.gif)

## Installation

Requirements: `virtualenv`, and `python3.8+`

1. `git clone https://github.com/d1vious/zoidbergstrike && cd zoidbergstrike` Clone project and cd into the project dir.
2. `pip install virtualenv && virtualenv -p python3 venv && source venv/bin/activate && pip install -r requirements.txt` Create Virtualenv and install requirements.

Continue to [configuring](#configuration) for SecurityTrails, Shodan, or ZoomEye API key.

### Configuration [`zoidbergstrike.conf`](https://github.com/d1vious/zoidbergstrike/blob/master/zoidbergstrike.conf.example)

Copy `zoidbergstrike.conf.example` to `zoidbergstrike.conf`!

Make sure to set a token for one of the available [providers](https://github.com/d1vious/zoidbergstrike/blob/main/zoidbergstrike.conf.example#L18-L25). If you need to create one for your account follow [these](htt://need wiki page) instructions.

Configuration example:

```
[global]
output = results.json
# stores matches in JSON here

log_path = zoidbergstrike.log
# Sets the log_path for the logging file

log_level = INFO
# Sets the log level for the logging
# Possible values: INFO, ERROR, VERBOSE

nse_script = grab_beacon_config.nse
# path to the nse script that rips down cobalt configs. This is specifically using https://github.com/whickey-r7/grab_beacon_config

searches = search.yml
# contains the different searches to run on each internet scanning service provider (eg shodan, zoomeye, security trails) when hunting for team servers.

shodan_token = TOKENHERE
# shodan token for searching

zoomeye_token = TOKENHERE
# zoomeye token for searching

securitytrails_token = TOKENHERE
# security trails token for searching
```

### Search The Internet

To modify the default mining performed across different providers, customize `search.yml`. The default ZoidbergStrike [Search Examples](#search-examples) below.

Run:

`python zoidbergstrike.py`

### Search IP list
populate `ips.txt` with potential Cobalt Strike C2 IPs a new line delimeted, example:

```
1.1.1.1
2.2.2.2
3.3.3.3
```

Run:

`python zoidbergstrike.py -i ips.txt`

If you need inspiration from hunters we highly recommend:

* [The DFIR Report](https://twitter.com/TheDFIRReport)
* [Awesome-Cobalt-Strike](https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence)
* [CobaltStrikeBot](https://twitter.com/cobaltstrikebot)

## Usage

```
usage: zoidbergstrike.py [-h] [-c CONFIG] [-o OUTPUT] [-v] [-i INPUT]

scans for open cobalt strike team servers and grabs their beacon configs and write this as a json log to be analyzed by any analytic tools
like splunk, elastic, etc..

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        config file path
  -o OUTPUT, --output OUTPUT
                        file to write to the results, defaults to results.json.log
  -v, --version         shows current zoidbergstrike version
  -i INPUT, --input INPUT
                        newline delimeted file of cobalt strike server ips to grab beacon configs from. example ips.txt
```

### Search Examples

The following searches are provided out of the box and more may be added to [`search.yml`](https://github.com/d1vious/zoidbergstrike/blob/main/search.yml) for more data.

#### Shodan

##### Find specific [JARM](https://blog.cobaltstrike.com/2020/12/08/a-red-teamer-plays-with-jarm/) signatures, out of the box we track Cobalt Strike 4.x
`'ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1'`

##### Team server detected by Shodan
`'product:"cobalt strike team server"'`

_note_: will generate alot of noisy results

##### Team server certificate serial
`'ssl.cert.serial:146473198'`

#### SecurityTrails

##### Find specific [JARM](https://blog.cobaltstrike.com/2020/12/08/a-red-teamer-plays-with-jarm/) signatures
`'SELECT address, ports.port FROM ips WHERE jarm = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"'`

# Author

* Michael Haag [@M_haggis](https://twitter.com/M_haggis)
* Jose Hernandez [@d1vious](https://twitter.com/d1vious)

# Credits & References

Inspiration came from a handful of blogs:
Much of this is only possible because whiskey-7 shared with us grab_beacon_config.nse

# TODO
- [ ] add zoomeye
- [ ] Dedup results before nmap
- [ ] add checking for latest updated
