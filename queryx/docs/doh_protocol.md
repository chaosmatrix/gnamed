# DOH Protocol

Use HTTP/HTTPS protocol

## Protocol
for security, should always use `HTTPS`.

## Common Format

### JSON

aka. Google HTTPDNS JSON, first use by Google HTTPDNS.

##### Content-Type / Accept

Normaly, require header `Accept: application/dns-json`,
different DOH Server might has different Headers requires.

##### Example
Request:
```
curl --http2 -H 'accept: application/dns-json' https://1.1.1.1/dns-query?name=example.com&type=a
```

Response:
```
{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": true,
  "CD": false,
  "Question": [
    {
      "name": "example.com",
      "type": 1
    }
  ],
  "Answer": [
    {
      "name": "example.com",
      "type": 1,
      "TTL": 85806,
      "data": "93.184.216.34"
    }
  ]
}
```

### RFC8484

aka. Google HTTPDNS JSON, first use by Google HTTPDNS.

##### Content-Type / Accept

as RFC8484 require, http header `Accept: application/dns-message` should be set.

##### Example
