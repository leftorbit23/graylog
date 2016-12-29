## Create cert and key for nxlog

*create nxlog-rules.cnf*

```
# Whether this certificate will be used to encrypt data (needed
# in TLS RSA ciphersuites). Note that it is preferred to use different
# keys for encryption and signing.
encryption_key

# Whether this certificate will be used for a TLS client
tls_www_server

expiration_days = 3650
```




certtool --generate-privkey --bits 2048 --outfile private/nxlog.key

certtool --generate-request --bits 2048 --load-privkey private/nxlog.key --outfile private/nxlog.csr

certtool --generate-certificate --bits 2048 --load-request private/nxlog.csr --outfile certs/nxlog.crt --load-ca-certificate certs/logstash-ca.crt --load-ca-privkey private/logstash-ca.key --template logstash-rules.cnf

## Add cert and key to nxlog config

```
<Output out> 
    Module      om_ssl
    Host        dmzlogserver
    Port        12201
    CAFile      %ROOT%\tls\logstash-ca.crt
    CertFile    %ROOT%\tls\nxlog.crt
    CertKeyFile %ROOT%\tls\nxlog.key

    #AllowUntrusted  TRUE
    #OutputType  GELF
    OutputType  LineBased
    Exec        to_json();
</Output>
```


## Enable ssl_verity in logstash


```
input {
  tcp {
    port => 12201
    type => "nxlogs"
    ssl_extra_chain_certs => ["tls/logstash-ca.crt"]
    ssl_cert => "tls/logstash.crt"
    ssl_key => "tls/logstash.key"
    ssl_enable => true
    ssl_verify => true
  }
}

```
