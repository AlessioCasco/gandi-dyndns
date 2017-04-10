gandi-dyndns
----
This simple app, lets you dynamicaly update a DNS record on [Gandi](https://www.gandi.net) registrar using any Cisco router, Cisco ASA firewall or device that is able to send its pubblic IP and fqdn (hostname + domain name) through a GET request.


### From 0 to running

#### Download the app
* git clone https://github.com/AlessioCasco/gandi-dyndns

#### Installation
* Install bottlepy `pip install bottle`
* Rename or copy 'config-test.json' to 'config.json'.

#### Configuration

##### config.json
Default config looks like this:

```json
{"port":"8080",
"bind":"0.0.0.0",
"apikey":"your_gandi_apy_key",
"logging":{
    "log_enable":"false",
    "log_level":"INFO",
    "log_file":"./gandi-dyndns.log"}
}
```
`port`- The HTTP port to listen on
`bind`- The address that should be bound to for comunication. By default, this is "0.0.0.0", meaning gandi-dyndns will bind to all addresses on the local machine.
`apikey`- Gandi apikey
`log_enable`- Enable or Disable logging to file
`log_level` - Log level to enable, possible values are: INFO, and DEBUG
`log_file` - Log file relative or absolute path

##### gandi
In this example, we suppose you want to manage `router.example.com`
* You must have a zone file on you gandi account named as your domain. e.g. example.com needs a zone file called example.com, if you don't have it, create it and link it to your example.com domain [here](https://www.gandi.net/admin/domain/zone/list)

* Now edit the zone just created and add a new A record for the router subdomain:

|Field  | Value     |         |
| ------|:---------:|--------:|
| Type  | A         |         |
| TTL   | 5         | minutes |
| Name  | router    |         |
| Value | 127.0.0.1 |         |

* Once done, click on the button `use this version` to make the new zone file active.

#### Usage
##### Starting
Simply run the script

```bash
./gandi-dyndns.py
```

```bash
./gandi-dyndns.py -c configfile
```
This app accepts one optional parameter `-c, --config` that defines the location of the config file, by default this config file has to be in the same directory where `gandi-dyndns.py` is.

##### Interacion
Now your router, firewall or network appliance (for info about how to configure a cisco appliances check the config section) can send updates to gandi-dyndns using `GET` method and the app will do the rest.

```
$machine_IP/DNS_name:$port/nic_update?ip=$IP&fqdn=$domain
```

To test the app manually (be aware that this may update your DNS name) issue this from your terminal:

```bash
curl -i "http:localhost:8080/nic_update?ip=1.1.1.1&fqdn=router.example.com
```


### HTTP status codes
* 200 => All good, 200 is given after updating the IP on Gandi and when there is no need to do so. 
* 400 => Bad request, some parameters are missing or not formatted correctly.
* 404 => Not found, No domain found associated with the Gandi API, zone file missing or A record not found into the zone file.


### Monitoring
You can monitor if the app is up and running by simply send GET requests to '/ping'

```bash
curl -i "http://localhost:8080/ping"

HTTP/1.0 200 OK
Date: Mon, 10 Apr 2017 22:05:08 GMT
Content-Length: 12
Server: gandi-dyndns
Content-Type: text/html; charset=UTF-8
Content-Type: text/html; charset=UTF-8

I'am alive!
```


### cisco configuration
* Coming soon


### Dependencies & Limitations

##### Dependencies
* [bottlepy](bottlepy.org)
* Gandi API. If you don't have it yet, enable the API from [Gandi](https://www.gandi.net/admin/api_key)

##### Limitations
* You must have a zone file on you gandi account named as your domain. e.g. example.com needs a zone file called example.com
* You can manage as many domains and subdomain as you want, but they all have to be owned by the same apikey.
* You will notice that gandi-dyndns sometimes needs quite a lot of time to respond with a 200 (~2s.), this is due to the slow nature of the Gandi API's.
* HTTPS is not available yet