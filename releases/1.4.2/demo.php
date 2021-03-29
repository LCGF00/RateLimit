<?php
require_once 'ratelimit/main.php'; // Import main file; Acts as an autoloader

use RateLimit\RateLimiter;

$limit = new RateLimiter( 10 ); // Construct a new RateLimiter Class with a setup of 10 requests per minute per Client

$response = $limit->limitClient(); // Configures the enviroment for the given client; fetches the request amount for that Client

if ($response->clientExceededMaxRequests()) { // Check if the Client has exceeded the maximum amount of requests
    
    http_response_code(429); // Set the HTTP Response Code to 429 (Too Many Requests) as the Client has exceeded the maximum amount of requests
    
}