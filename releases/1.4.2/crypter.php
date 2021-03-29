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

declare ( strict_types = 1 );

namespace RateLimit;

class Crypter {

    /*
     * Encrypt a message
     * 
     * @param string $message Message to encrypt
     * @param string $key Encryption key
     * @return string Encrypted String
     */
    
    protected function encrypt(string $message, string $key) : string {
        
        if ( mb_strlen ( $key, '8bit' ) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES ) {
            
            throw new RangeException( 'Key is not the correct size (must be 32 bytes).' );
            
        }
        
        $nonce = random_bytes ( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
        
        $cipher = base64_encode(
            $nonce.
            sodium_crypto_secretbox(
                $message,
                $nonce,
                $key
            )
        );
        
        sodium_memzero( $message );
        sodium_memzero( $key );
        
        return $cipher;
    }
    
    /*
     * Decrypt a Message
     * 
     * @param string $encrypted - Encrypted String
     * @param string $key Encryption Key
     * @return string Decrypted String
     */
     
    protected function decrypt( string $encrypted, string $key ) : string {
        
        $decoded = base64_decode( $encrypted );
        $nonce = mb_substr ( $decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit' );
        $ciphertext = mb_substr ( $decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit') ;
        
        $plain = sodium_crypto_secretbox_open(
            $ciphertext,
            $nonce,
            $key
        );
        
        if ( !is_string ( $plain ) ) {
            
            throw new Exception( 'Invalid MAC' );
            
        }
        
        sodium_memzero( $ciphertext );
        sodium_memzero( $key );
        
        return $plain;
    }
}