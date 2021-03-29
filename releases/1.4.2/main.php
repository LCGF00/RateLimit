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
require_once 'response.php';

error_reporting(E_ALL);

final class RateLimiter extends Response {
    
    /*
     * @const VERSION The current script version
     */
    
    public const VERSION = "1.4.2";
    
    /*
     * @var int $requestsPerMin Amount of Requests allowed per minute per Client
     * @var string $storageDir Storage Directory
     * @var string $storageKey Encryption/Decryption Key
     */
    
    protected $requestsPerMin;
    protected $storageDir;
    protected $storageKey;
    
    
    /*
     * Constructor
     *
     * @param int $requestsPerMin Amount of Requests allowed per minute per Client
     * @return bool true|false Whether the Library was constructed successfully
     */
    
    public function __construct ( int $requestsPerMin ) {
        
        ignore_user_abort(true);
        
        if (!extension_loaded("sodium")) {
            throw new RateLimitBuildException( "Missing libsodium extension, please install it in order to use this script" );
        }
        
        if ( $requestsPerMin < 1 ) {
            
             throw new RateLimitBuildException ( "Requests Per Minute must be bigger than 1" );
             
             return false;
            
        } else {
        
            $this->requestsPerMin = $requestsPerMin;
   
        }
        
        $this->setStorage ( __DIR__ . "/bin" );
        
        return true;
        
    }
    
    /*
     * Set Storage Directory
     *
     * @param string $dir Directory Path
     */
    
    protected function setStorage( string $dir ) {
        if ( !is_dir ( $dir ) ) {
            
            throw new RateLimitBuildException ( "Invalid Directory: " . $dir );
            
        } else {
            
            $this->storageDir = $dir;
            
            if ( !@file_exists( $dir . "/ratelimiter.key" ) ) {
                
                $file = @fopen( $dir . "/ratelimiter.key", "x+" );
                
                if ( $file !== false ) {
                    
                    $random_key = random_bytes( SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
                    
                    if ( @fwrite( $file, $random_key ) ) {

                        $file2 = @fopen( $dir . "/ratelimiter.key", "r" );                        
                        $key = fread( $file2, filesize( $dir . "/ratelimiter.key" ) );
                        
                        if ( !empty( $key ) ) {
                            
                            $this->storageKey = $key;
                            
                        } else {
                            
                            throw new RateLimitException( "Internal Error: Could not read Key File" );
                            
                        }
                        
                    } else {
                        
                        throw new RateLimitException( "Internal Error: Could not write to Key File" );
                        
                    }
                    
                } else {
                    
                    throw new RateLimitException( "Internal Error: Could not create Key File" );
                    
                }
                
                fclose($file);
            } else {
                
                $file = @fopen( $dir . "/ratelimiter.key", "r+" );
                
                if ( $file ) {
                
                    $key = @fread( $file, filesize( $dir . '/ratelimiter.key' ) );
                    
                    if ( $key ) {
                        
                        $this->storageKey = $key;
                        
                    } else {
                        
                        throw new RateLimitException( "Internal Error: Could not read Key File" );
                        
                    }
                } else {
                    
                    throw new RateLimitException( "Internal Error: Could not read Key File" );
                    
                }
                fclose($file);
            }
            
        }
    }
    
    /*
     * Get Storage File
     *
     * @param string $ip Client IP Address
     * @return string $file The file associated with the IP Address
     * @info Creates a new file for IP if one doesn't exist
     */
    
    private function getStorageFile ( string $ip ) : string {
        
        if ( empty ( $this->storageDir ) ) {
            throw new RateLimitException ( "Could not locate Storage Directory (" . $this->storageDir . ")" );
        }
        
        if ( empty ( $this->storageKey ) ) {
            throw new RateLimitException ( "Could not locate Key File " );
        }
        
        $file = @fopen( $this->storageDir . "/ratelimiter.key", "r+" );
                
        if ( $file !== false ) {
        
            $key = @fread( $file, filesize( $this->storageDir . '/ratelimiter.key' ) );
            
            if ( $key !== false ) {
                
                if ( $handle = opendir ( $this->storageDir ) ) {
                    
                    $foundIp = false;

                    while ( false !== ( $entry = readdir ( $handle ) ) ) {
                
                        if ( $entry != "." && $entry != ".." ) {
                
                            if ( $this->isBase64 ( $entry ) ) {
                    
                                if ( $this->decrypt ( $this::base64url_decode ( $entry ) , $key ) == $ip ) {
                                    
                                    $foundIp = true;
                                    
                                    $GLOBALS["file_data"] = $this->decrypt ( fread( fopen( $this->storageDir . "/" . $entry, "r") , filesize( $this->storageDir . "/" . $entry ) ), $key );
                                    
                                    return $GLOBALS["file_data"];
                                }
                            }
                        }
                    }
                
                    closedir( $handle );
                    
                    if ( $foundIp == false ) {
                        
                        $fileName = $this::base64url_encode ( $this->encrypt ( $ip, $this->storageKey ) );
                        
                        $file2 = @fopen( $this->storageDir . "/" . $fileName,  "x+");
                        
                        
                        if ( $file2 !== false ) {
                            
                            $contents = $this->encrypt ( json_encode( [
                                
                                "last_request" => date ( "i", time() ) ,
                                "requests" => 1,
                                "ip" => $ip
                                
                            ] ), $this->storageKey );
                            
                            if ( @fwrite ( $file2 , $contents ) ) {
                                
                                return $this->getStorageFile ( $ip );
                                
                            }
                            
                        } else {
                            
                            throw new RateLimitException ( "Internal Error: Could not create file for client" );
                               
                        }
                        
                        fclose($file2);
                    }
                } else {
                    
                    throw new RateLimitException ( "Internal Error: Could not read storage directory" );
                    
                }
                
            } else {
                
                throw new RateLimitException( "Internal Error: Could not read Key File" );
                
            }
        } else {
            
            throw new RateLimitException( "Internal Error: Could not read Key File" );
            
        }
        
        fclose($file);
        
        return "";
        
    }
    
    /*
     * Update Storage File
     *
     * @param string $ip Client IP Address
     * @param object $data The current data associated with the IP Address
     * @return bool true|false Whether it was successfully updated or not
     * @info Adds 1 to the total request amount, resets it to 1 if the current minute has changed
     */
    
    private function updateRequest ( string $ip, object $data ) : bool {
        
        if ( empty ( $this->storageDir ) ) {
            throw new RateLimitException ( "Could not locate Storage Directory (" . $this->storageDir . ")" );
        }
        
        if ( empty ( $this->storageKey ) ) {
            throw new RateLimitException ( "Could not locate Key File " );
        }
        
        $file = @fopen( $this->storageDir . "/ratelimiter.key", "r+" );
                
        if ( $file !== false ) {
        
            $key = @fread( $file, filesize( $this->storageDir . '/ratelimiter.key' ) );
            
            if ( $key !== false ) {
                
                if ( $handle = opendir ( $this->storageDir ) ) {
                    
                    $foundIp = false;

                    while ( false !== ( $entry = readdir ( $handle ) ) ) {
                
                        if ( $entry != "." && $entry != ".." ) {
                
                            if ( $this->isBase64 ( $entry ) ) {
                    
                                if ( $this->decrypt ( $this::base64url_decode ( $entry ) , $key ) == $ip ) {
                                    
                                    $foundIp = true;
                                    
                                    $GLOBALS["client_file"] = $entry;
                                    
                                }
                            }
                        }
                    }
                
                    closedir( $handle );
                    
                    if ( $foundIp === false ) {
                        
                        throw new RateLimitException ( "Internal Error: Could not locate file for client" );
                        
                    } else {
                        
                        if ( $file = @fopen ( $this->storageDir . "/" . $GLOBALS["client_file"], "r+" ) ) {
                            
                            if ( $data->last_request !== date ( "i", time() ) ) {
                            
                                $contents = $this->encrypt ( json_encode( [
                                    
                                    "last_request" => date ( "i", time() ) ,
                                    "requests" => 1,
                                    "ip" => $ip
                                    
                                ] ), $this->storageKey );
                                
                            } else {
                                
                                $contents = $this->encrypt ( json_encode( [
                                    
                                    "last_request" => date ( "i", time() ) ,
                                    "requests" => $data->requests + 1,
                                    "ip" => $ip
                                    
                                ] ), $this->storageKey );
                                
                            }
                            
                            if ( @fwrite ( $file, $contents ) ) {
                                
                                return true;
                                
                            } else {
                                
                                throw new RateLimitException ( "Internal Error: Could not write to client file" );
                                
                            } 
                            
                        } else {
                            
                            throw new RateLimitException ( "Internal Error: Could not read file for client" );
                            
                        }
                    }
                }
                
            } else {
                
                throw new RateLimitException ( "Internal Error: Could not read Key File" );
                
            } 
        } else {
            
            throw new RateLimitException ( "Internal Error: Could not open Key File" );
            
        }
        return false;
    }
    
    /*
     * Limit Client
     *
     * @return object $response Request Response
     * @info Fetches & Updates the data associated with the IP Address
     */
    
    public function limitClient () {
        
        $ip = $this->getClientIp ();
        
        
        $req_data = json_decode ( $this->getStorageFile ( $ip ) );
        
        $this->updateRequest ( $ip , $req_data );
        
        $req_data = json_decode ( $this->getStorageFile ( $ip ) );
        
        return new Response ( $this->requestsPerMin, $req_data->requests );
    }
    
    /*
     * Fetches Client IP Address
     *
     * @return string $ip Client IP Address
     */
    
    private function getClientIp () {
        
        if ( isset($_SERVER) ) {
    
            if ( isset($_SERVER["HTTP_X_FORWARDED_FOR"]) )
            
                return $_SERVER["HTTP_X_FORWARDED_FOR"];
    
            if ( isset($_SERVER["HTTP_CLIENT_IP"]) )
            
                return $_SERVER["HTTP_CLIENT_IP"];
    
            return $_SERVER["REMOTE_ADDR"];
        }
    
        if ( getenv('HTTP_X_FORWARDED_FOR') )
        
            return getenv('HTTP_X_FORWARDED_FOR');
    
        if ( getenv('HTTP_CLIENT_IP') )
        
            return getenv('HTTP_CLIENT_IP');
    
        return getenv('REMOTE_ADDR');
        
    }
    
    /*
     * Is Base64
     *
     * @param string $base64_string A string to be tested as Base64
     * @return bool true|false Whether the given string is valid Base64 or not
     */
    
    protected function isBase64( $base64_string ) {
        return (bool) preg_match( '/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', $base64_string );
    }
    
    /*
     * Base64 URL Encode
     *
     * @param string $data A string to be encoded as URL-Safe Base64
     * @return string $base64 URL-Safe Base64 String
     */
    
    protected static function base64url_encode ($data) :string {
        return rtrim( strtr ( base64_encode ( $data ), '+/', '-_' ), '=' );
    }
    
    /*
     * Base64 URL Decode
     *
     * @param string $base64 Base64 String to be decoded
     * @return string $data Decoded Base64 String
     */
    
    protected static function base64url_decode ( $data ) :string {
        return base64_decode ( str_pad( strtr ( $data, '-_', '+/' ), strlen( $data ) % 4, '=', STR_PAD_RIGHT ) );
    }
    
    /*
     * Destructor
     *
     * @info Resets ignore_user_abort to false
     */
    
    public function __destruct () {
        
        ignore_user_abort(false);
       
    }
    
}
