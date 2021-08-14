# Odd Eye

![](https://media.discordapp.net/attachments/418699380833648644/876139165387989002/unknown.png?width=1440&height=373)

<p align="center">
  Detect bad bots trying to disguise themselves as humans.
</p>


## Features

- [x] [HTTP2 connection fingerprints](https://github.com/Xetera/nginx-http2-fingerprint)
- [x] [TLS signatures](https://github.com/salesforce/ja3)
- [ ] [Canvas fingerprints](https://research.google/pubs/pub45581/)

## How it works

Odd eye is a standalone fingerprinting server that lives separate from the rest of your infrastructure and turns low-level information about the connections it receives into tokens that can be checked to expose bots that are lying about their identity.

Collected fingerprints are encrypted using **XChaCha20-Poly1305** with a symmetric key shared across your services before being returned to the caller. This fingerprint can be sent to any other service in your infrastructure without worrying about modifying the reverse proxy in front of the APIs that need fingerprint information, as bots will be forced to hand over their real identity to make successful requests.

## Usage

Set a 256 bit variable as the encryption key or autogenerate it.

`export ODD_EYE_ENCRYPTION_KEY=$(openssl rand -hex 16)`

1. Build the NGINX container `cd nginx && docker-compose up --build -d`
2. Run the origin webserver on port 4000 `cargo run`
3. Go to https://localhost

Modify the `./nginx/docker/nginx.conf` file to your liking for development or mount it under `/usr/local/nginx/conf/nginx.conf`

- `GET /` - Return the encrypted fingerprint of the request in binary format.
- `GET /b64` - Return the encrypted fingerprint of the request in base 64 format.
- `GET /test` - Return the plaintext fingerprint of the request for testing (disabled in release mode).

Example response
```json
{
  "fingerprint": {
    "http": "1:65536;3:1000;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p",
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-21,29-23-24,0",
    "ja3_hash": "3e9b20610098b6c9bff953856e58016a",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"
  },
  "timestamp": "2021-08-14T15:10:48.085487989Z"
}
```

```
Nonce (24 bytes)         | Encrypted Payload
-------------------------|-------------------------------
sOS97Zf8E0BI5gkEHRNk243G | 💃 🍋 💴 🙂 🕵 😷 💝 🔗 📦 🍰
```

The first 24 bytes of the message should be sliced out as the nonce to decrypt the encrypted payload with the shared secret.

The submitted nonce must be checked for uniqueness in order to prevent replay attacks.

The API will respond with an `application/octet-stream` when generating fingerprints by default. If you need it in text format you can hit up the `/b64` endpoint instead

```js
const key = await fetch("https://boca.yoursite.com/b64").then(res => res.text())

await fetch("https://api.yoursite.com/purchase", {
  method: "POST",
  headers: {
    "x-identity": key
  },
  body: JSON.stringify(...)
});
```

## Why

Currently, big cloud security companies have a monopoly on fingerprinting methods used to analyze traffic and even though the data collection methods are open source, they don't the data itself with their customers in order to feed the data into their ML models to sell expensive bot protection services.

This information should be easily accessible for all site owners to deal with unwanted traffic without paying thousands of dollars. Of course, this isn't a replacement for Cloudflare's enterprise bot protection by any means, but it helps raise the bar.

## Limitations

**This repo is a proof of concept with many flaws. If you want to use it in production, you're warned.**

#### Reverse proxies
Because cloud proxy services like Cloudflare and Akamai do TLS termination and handle other parts of the connection, fingerprints get lost as these services replay requests through their custom http stacks and don't mirror the requests they receive 1 to 1. This unfortunately means you cannot benefit from putting any reverse proxy/load balancer in front of the custom NGINX image. You can still use Cloudflare for DNS but you cannot turn on the orange cloud.

#### Priority frames 
Requests made to odd eye are only a single GET request. Browsers like Firefox which are normally more aggressive with how many connections they try to open compared to others won't attempt to behave the same with odd eye because of a lack of resources being accessed. This would normally show up in the form of multiple PRIORITY frames in the HTTP2 fingerprint.

In theory, to get around this, a client should be able to try loading multiple resources from the fingerprinting server at the same time to normalize the browser inconsistencies. I haven't been able to get this behavior to work though.

#### HTTP2 
Clients that don't support http2 can only receive limited fingerprint information. This should be taken into account when analyzing fingerprints on the service-side.

#### TLS 
All connecting clients must support TLS. This is already something that should be enforced, but can make testing a little more tedious working with self-signed certificates.

#### Reliability

None of these metrics are a silver bullet to detecting bots. There are going to be plenty of false positives as browsers change their behaviors and false negatives as your site becomes a bigger target for the red team (👋). Fingerprinting is just a piece of the abuse detection puzzle. The goal is to make automation as frustrating and expensive as possible, not impossible.