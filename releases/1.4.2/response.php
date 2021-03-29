<?php
/*
 * PHP Rate Limiting Library v.1.4.2
 * PHP Version ^7.4
 *
 * Copyright 2021 TBM Productions
 * https://tbmproduction.com/license
 *
 * https://developer.tbmproduction.com/docs/ratelimit
 */

namespace RateLimit;

require_once 'exception.php';
require_once 'crypter.php';

class Response extends Crypter {
    
    /*
     * @var int $maxRequests Amount of Requests allowed per minute per Client
     * @var int $currentRequests Amount of Requests for current Client
     */
    
    private $maxRequests;
    private $currentRequests;
    
    /*
     * Constructor
     *
     * @param int $maxRequests Amount of Requests allowed per minute per Client
     * @param int $currentRequests Amount of Requests for current Client
     */
    
    public function __construct ( int $maxRequests, int $currentRequests ) {
        
        $this->maxRequests = $maxRequests;
        $this->currentRequests = $currentRequests;
        
    }
    
    /*
     * Has the Client Exceeded Max Requests
     *
     * @return bool true|false Whether the Client has exceeded the maxium amount of Requests
     */

    public function clientExceededMaxRequests () : bool {
        
        if ( $this->currentRequests > $this->maxRequests ) {
            
            return true;
            
        } else {
            
            return false;
            
        }
    }
}