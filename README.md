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

## Configuration [`zoidbergstrike.conf`](https://github.com/d1vious/zoidbergstrike/blob/master/zoidbergstrike.conf.example)

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

## Search Examples

The following searches are provided out of the box and more may be added to [`search.yml`](https://github.com/d1vious/zoidbergstrike/blob/main/search.yml) for more data.

#### Shodan

##### Find specific [JARM](https://blog.cobaltstrike.com/2020/12/08/a-red-teamer-plays-with-jarm/) signatures, out of the box we track Cobalt Strike 4.x
`'ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1'`

##### Filter by HTTP headers and ports to reduce noisy results
`'ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1 port:"22, 80, 443, 444, 1234, 2000, 2222, 3000, 3780, 4000, 4443, 6379, 7443, 8443, 8080, 8081, 8082, 8087, 8088, 8099, 8089, 8090, 8181, 8888, 8889, 9443, 50050" HTTP/1.1 404 Not Found Content-Length: 0'`

##### Team server detected by Shodan
`'product:"cobalt strike team server"'`

_note_: will generate lots of noisy results, do not actually schedule this unless you want to burn your license credits.

##### Team server certificate serial
`'ssl.cert.serial:146473198'`

#### SecurityTrails

##### Find specific [JARM](https://blog.cobaltstrike.com/2020/12/08/a-red-teamer-plays-with-jarm/) signatures
`'SELECT address, ports.port FROM ips WHERE jarm = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"'`

##### Filter by HTTP Headers and ports to reduce noisy nmap_results
`'SELECT address, ports.port, isp.name_normalized, ports.port, address, asn.number, jarm, http.headers.raw FROM ips WHERE jarm = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1" OR jarm = "07d14d16d21d21d07c07d14d07d21d9b2f5869a6985368a9dec764186a9175" OR jarm = "2ad2ad16d2ad2ad22c42d42d00042d58c7162162b6a603d3d90a2b76865b53" AND http.headers.content_type = "text/plain" AND http.headers.raw = "content-length:0" AND ports.port IN (22, 80, 443, 444, 1234, 2000, 2222, 3000, 3780, 4000, 4443, 6379, 7443, 8443, 8080, 8081, 8082, 8087, 8088, 8099, 8089, 8090, 8181, 8888, 8889, 9443, 50050)'`

## Author

* Michael Haag [@M_haggis](https://twitter.com/M_haggis)
* Jose Hernandez [@d1vious](https://twitter.com/d1vious)

## Support 📞
Please use the [GitHub issue tracker](https://github.com/splunk/attack_range/issues) to submit bugs or request features.

If you have questions or need support, you can:

* Join the [#security-research](https://splunk-usergroups.slack.com/archives/C1S5BEF38) room in the [Splunk Slack channel](http://splunk-usergroups.slack.com)

## Credits & References

Inspiration came from a handful of blogs:
Much of this is only possible because whiskey-7 shared with us grab_beacon_config.nse

## TODO
- [ ] add zoomeye
- [ ] Dedup results before nmap
- [ ] add checking the most recent result by looking at the latest_updated field

## License
Copyright 2020 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
