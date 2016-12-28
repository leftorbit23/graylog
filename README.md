# Secure log collection from DMZ

The steps outlined below will demonstrate how to securely transmit logs from the DMZ to an internal Graylog server. This method uses TLS to encrypt all communication and does not require any new inbound rules on the firewall. In my examples I will be using Windows based servers and clients. 



## Dataflow

- NXLog collects windows eventlogs from clients in the DMZ
- NXLog coverts log data to JSON
- NXLog sends log data to Logstash via encrypted TLS connection
- Logstash send data to RabbitMQ
- Graylog retrieves data from RabbitMQ
- Graylog extracts data from JSON 

We will be using the following servers in this example:

- dmzserver - existing server you wish to collect logs from
- dmzlogserver - new server you will build to host Logstash and RabbitMQ in the DMZ
- graylogserver - existing Graylog server you wish to deliver the logs to


## Build new windows log server


Minimum Hardware Requirements:

* 1 Ghz CPU
* 2 GB RAM
* 40 GB Drive

Standard Windows Server install.

This computer does not need to be joined to the domain.

## Generate certificates and keys for NXLog/Logstash

Note: I ran the following on a Linux computer that already had certtools installed. If you're planning to run them in Windows you'll need to download the tools [here](http://www.gnutls.org/download.html)


mkdir ~/nxlog-logstash
cd ~/nxlog-logstash/logstash
mkdir certs private
certtool --generate-privkey --bits 2048 --outfile private/logstash-ca.key

*create logstash-ca-rules.cnf*

```
# Whether this is a CA certificate or not
ca

expiration_days = 3650
```

certtool --generate-self-signed --load-privkey private/logstash-ca.key --bits 2048 --template logstash-ca-rules.cnf --outfile certs/logstash-ca.crt


*create logstash-rules.cnf*

```
# Whether this certificate will be used to encrypt data (needed
# in TLS RSA ciphersuites). Note that it is preferred to use different
# keys for encryption and signing.
encryption_key

# Whether this certificate will be used for a TLS client
tls_www_server

expiration_days = 3650
```

certtool --generate-privkey --bits 2048 --outfile private/logstash.key

certtool --generate-request --bits 2048 --load-privkey private/logstash.key --outfile private/logstash.csr

certtool --generate-certificate --bits 2048 --load-request private/logstash.csr --outfile certs/logstash.crt --load-ca-certificate certs/logstash-ca.crt --load-ca-privkey private/logstash-ca.key --template logstash-rules.cnf




## Install NXLog on dmzserver
- [Download NXLog](https://nxlog.co/system/files/products/files/1/nxlog-ce-2.9.1716.msi)
- Install NXLog to default location
- Copy logstash-ca.crt generated in the previous step to **C:\Program Files (x86)\nxlog\tls\logstash-ca.crt**
- Replace **C:\Program Files (x86)\nxlog\conf\nxlog.conf** with the following configuration


```
## This is a sample configuration file. See the nxlog reference manual about the
## configuration options. It should be installed locally and is also available
## online at http://nxlog.org/nxlog-docs/en/nxlog-reference-manual.html

## Please set the ROOT to the folder your nxlog was installed into,
## otherwise it will not start.

#define ROOT C:\Program Files\nxlog
define ROOT C:\Program Files (x86)\nxlog

Moduledir %ROOT%\modules
CacheDir %ROOT%\data
Pidfile %ROOT%\data\nxlog.pid
SpoolDir %ROOT%\data
LogFile %ROOT%\data\nxlog.log

<Extension json>
    Module	xm_json
</Extension>

<Input in>
    # For windows vista/2008 and above use:
    Module      im_msvistalog

    # For windows 2003 and earlier use the following:
    #   Module      im_mseventlog
</Input>

<Output out> 
    Module      om_ssl
    Host        dmzlogserver
    Port        12201
    CAFile      %ROOT%\tls\logstash-ca.crt
    #AllowUntrusted  TRUE
    OutputType  LineBased
    Exec        to_json();
</Output>

<Route 1>
    Path	in => out
</Route>

```



## Install Logstash on dmzlogserver

- [Download and install Java SE Development Kit 8u112]( http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html).
  - Add new system environment variable (System -> Change Settings -> Advanced -> Environment Variables -> New)
    - Variable Name: JAVA_HOME
    - Variable Value: C:\Program Files\Java\jdk1.8.0_112

- [Download Logstash](https://artifacts.elastic.co/downloads/logstash/logstash-5.1.1.zip).
  - Uncompress Logstash to C:\Logstash
  - Copy logstash-ca.crt, logstash.crt and logstash.key generated in the previous steps to C:\logstash\config\tls\
  - Save the following config file to C:\logstash\config\logstash.json
```
input {
  tcp {
    port => 12201
    type => "nxlogs"
    ssl_extra_chain_certs => ["tls/logstash-ca.crt"]
    ssl_cert => "tls/logstash.crt"
    ssl_key => "tls/logstash.key"
    ssl_enable => true
    ssl_verify => false
  }
}

output {
  stdout {
    id => "debug_stdout"
  }
 
  rabbitmq {
    exchange => "log-messages"
    exchange_type => "fanout"
    key => "log-messages"
    host => "localhost"
    workers => 1 
    durable => true
    persistent => true
    port => 5672
    user => "rabbitmquser"
    password => "rabbitmqpassword"
  }
}
```

### NSSM Install on dmzlogserver

- Download NSSM [here](https://nssm.cc/release/nssm-2.24.zip)
  - NSSM will allow Logstash to run as a windows service.

From command-line run the following:
```
C:\NSSM\win64\nssm install Logstash
```

- Application (tab)
  - Path: C:\logstash\bin\logstash.bat
  - Startup directory: C:\logstash\bin\
  - Arguments: C:\logstash\config\logstash.json
  - Service name: Logstash
- Details (tab)
  - Display name: Logstash
  - Description: Logstash Service
  - Startup type: Automatic
- Click Install Service

Start Logstash Service

## Generate certificates for RabbitMQ

Follow the steps here: https://www.rabbitmq.com/ssl.html

Copy the generated files (cacert.pem, cert.pem, key.pem) to %APPDATA%\RabbitMQ\tls

Replace %APPDATA%\RabbitMQ\rabbitmq.config with the following:

```
[
{rabbit, [
           {tcp_listeners, [5672] },
           {ssl_listeners, [5673] },
           {ssl_options, [
             {cacertfile, "/Users/Administrator/AppData/Roaming/RabbitMQ/tls/cacert.pem" },
             {certfile, "/Users/Administrator/AppData/Roaming/RabbitMQ/tls/cert.pem" },
             {keyfile, "/Users/Administrator/AppData/Roaming/RabbitMQ/tls/key.pem" },
%%           {verify, verify_peer},
             {versions, ['tlsv1.2', 'tlsv1.1']},
             {fail_if_no_peer_cert, true }
           ]}
         ]}
].

```

## Install RabbitMQ on dmzlogserver

- [Download Erland Windows 64-bit Binary File](http://www.erlang.org/downloads)
  - Install Erlang
- [Download RabbitMQ](https://www.rabbitmq.com/releases/rabbitmq-server/v3.6.6/rabbitmq-server-3.6.6.exe)
  - Install RabbitMQ

Create a new user account for RabbitMQ and delete the default **guest** user:

From command-line run the following:
```
cd C:\Program Files\RabbitMQ Server\rabbitmq_server-3.6.6\sbin

rabbitmqctl.bat add_user rabbitmquser rabbitmqpassword
rabbitmqctl.bat set_permissions rabbitmquser ".*" ".*" ".*"
rabbitmqctl.bat delete_user guest
```

Start RabbitMQ Service

## Configure Graylog input to pull data from RabbitMQ


### Congiure input

Open Graylog GUI

Open System / Inputs -> Inputs

Select input - Raw/Plaintest AMQP (Launch new input)
```
Title: Windows Server Eventlog (DMZ)
Exchange: log-messages
Queue: log-messages
Broker hostname: **dmzlogserver**
Username: rabbitmquser
Check Bind to exchange
Password: rabbitmqpassword
Check Enable TLS
SAVE
```

### Configure input extractors

Click Manage extractors

Click Actions -> Import extractors

Use the following:

```
{
  "extractors": [
    {
      "title": "a",
      "extractor_type": "json",
      "converters": [],
      "order": 0,
      "cursor_strategy": "cut",
      "source_field": "message",
      "target_field": "",
      "extractor_config": {
        "list_separator": ", ",
        "kv_separator": "=",
        "key_prefix": "",
        "key_separator": "_",
        "replace_key_whitespace": false,
        "key_whitespace_replacement": "_"
      },
      "condition_type": "none",
      "condition_value": ""
    },
    {
      "title": "b",
      "extractor_type": "json",
      "converters": [],
      "order": 0,
      "cursor_strategy": "cut",
      "source_field": "message",
      "target_field": "",
      "extractor_config": {
        "list_separator": ", ",
        "kv_separator": "=",
        "key_prefix": "",
        "key_separator": "_",
        "replace_key_whitespace": false,
        "key_whitespace_replacement": "_"
      },
      "condition_type": "none",
      "condition_value": ""
    },
    {
      "title": "c",
      "extractor_type": "copy_input",
      "converters": [],
      "order": 0,
      "cursor_strategy": "copy",
      "source_field": "Hostname",
      "target_field": "source",
      "extractor_config": {},
      "condition_type": "none",
      "condition_value": ""
    },
    {
      "title": "d",
      "extractor_type": "copy_input",
      "converters": [],
      "order": 0,
      "cursor_strategy": "cut",
      "source_field": "Message",
      "target_field": "message",
      "extractor_config": {},
      "condition_type": "none",
      "condition_value": ""
    }
  ],
  "version": "2.1.0-SNAPSHOT"
}

```

Make sure the extractors are in alphabetical order

# Troubleshooting

## NXLog

The log file can be found in C:\Program Files (x86)\nxlog\data\nxlog.log

## Logstash

Stop the Logstash service and run the following from command line:

```
cd C:\logstash\
C:\logstash\bin\logstash.bat -f C:\logstash\config\logstash.json
```

## RabbitMQ

The log file can be found in %AppData%\RabbitMQ

## TLS

openssl s_client -CAfile certs/logstash-ca.crt -connect dmzlogserver:12201

certtool -i --infile certs/nxlog.crt



# Source documentation/Credits:

https://github.com/Graylog2/graylog-guide-syslog-amqp

http://stackoverflow.com/questions/26789903/using-nxlog-to-ship-logs-in-to-logstash-from-windows-using-om-ssl

https://www.ulyaoth.net/resources/tutorial-install-logstash-and-kibana-on-a-windows-server.34/

https://www.rabbitmq.com/install-windows.html

https://www.rabbitmq.com/ssl.html

https://nxlog.co/docs/nxlog-ce/nxlog-reference-manual.html


