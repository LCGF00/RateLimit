# PHP Rate Limiting Client

A simple PHP Rate Limiting Script that allows developers to limit incoming requests.

### Install

Download:

Chose the version you want and download the files from that folder. Upload all these files to your website and then you'll be ready to go.

### Usage

First, lets import the main file:
```php
require_once 'ratelimit/main.php';
```

This file acts as an autoloader and will automatically import the needed files.

---
Create an Allias of the Main Class & Construct a new RateLimiter Class:
```php
use RateLimit\RateLimiter;
$limit = new RateLimiter( 10 );
```
This creates a new RateLimiter class that specifies all clients have a maximum of 10 requests per given minute.

---
Initate the script to fetch the amount of requests for the given Client:
```php
$response = $limit->limitClient(); 
```
---

Detect whether the client has exceeded the maximum amount of requests:
```php
if ($response->clientExceededMaxRequests()) {
	http_response_code(429);
}
```
This will set the HTTP Response Code to 429 (Too Many Requests) if the Client has exceeded the maximum amount of requests.

---

## Copyright Mumbo Jumbo

Lets keep it short, view the license at https://tbmproduction.com/license
