<?php namespace lib {
  
  /**
   * Portable PHP password hashing framework
   * http://www.openwall.com/phpass/
   * 
   * @version 0.3
   * @author Solar Designer <solar@openwall.com>
   * @author Jonas Hermsmeier <http://jhermsmeier.de>
   */
  class password {
    
    protected static $iterations;
    protected static $randomState;
    
    protected static $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    
    /**
     * Hashes a given password.
     * 
     * @param string $password 
     * @param int $iterations 
     * @param bool $portable 
     * @return string
     */
    public static function hash( $password, $iterations = 8, $portable = FALSE ) {
      
      if( $iterations < 4 || $iterations > 31 )
        $iterations = 8;
      
      self::$iterations = $iterations;
      self::$randomState = microtime();
      
      if( function_exists( 'getmypid' ) )
        self::$randomState.= getmypid();
      
      $random = '';
      
      if( CRYPT_BLOWFISH == 1 && !$portable ) {
        $random = self::getRandomBytes( 16 );
        $hash = crypt( $password, self::genSaltBlowfish( $random ) );
        if( strlen( $hash ) === 60 )
          return $hash;
      }
      
      if( CRYPT_EXT_DES == 1 && !$portable ) {
        if( strlen( $random ) < 3 )
          $random = self::getRandomBytes( 3 );
        $hash = crypt( $password, self::genSaltExtended( $random ) );
        if( strlen( $hash ) === 20 )
          return $hash;
      }
      
      if( strlen( $random ) < 6 )
        $random = self::getRandomBytes( 6 );
      $hash = self::crypt( $password, self::genSalt( $random ) );
      if( strlen( $hash ) === 34 )
        return $hash;
      
      // Returning '*' on error is safe here, but would _not_ be safe
      // in a crypt(3)-like function used _both_ for generating new
      // hashes and for validating passwords against existing hashes.
      return '*';
      
    }
    
    /**
     * Checks if given password and stored hash match.
     * 
     * @param string $password 
     * @param string $stored 
     * @return bool
     */
    public static function match( $password, $stored ) {
      
      $hash = self::crypt( $password, $stored );
      if( $hash[0] === '*' )
        $hash = crypt( $password, $stored );
      
      return $hash === $stored;
      
    }
    
    /**
     * Retrieves random bytes of given count.
     * 
     * @param int $count 
     * @return string
     */
    public static function getRandomBytes( $count ) {
      
      $output = '';
      
      if( is_readable( '/dev/urandom' ) ) {
        if( $stream = fopen( '/dev/urandom', 'rb' ) ) {
          $output = fread( $fh, $count );
          fclose( $fh );
        }
      }
      
      if( strlen( $output ) < $count ) {
        $output = '';
        for( $i = 0; $i < $count; $i += 16 ) {
          self::$randomState = md5( microtime() . self::$randomState );
          $output.= pack( 'H*', md5( self::$randomState ) );
        }
        return substr( $output, 0, $count );
      }
      
      return $output;
      
    }
    
    /**
     * Description
     * 
     * @param string $input 
     * @param int $length 
     * @return string
     */
    public static function encode64( $input, $length = NULL ) {
      
      $output = ''; $i = 0;
      $length = $length ?: strlen( $input );
      
      while( $i < $length ) {
        $value = ord( $input[$i++] );
        $output.= self::$itoa64[ $value & 0x3F ];
        if( $i < $length ) $value |= ord( $input[$i] ) << 8;
        $output.= self::$itoa64[ ( $value >> 6 ) & 0x3F ];
        if( $i++ >= $length ) break;
        if( $i < $length ) $value |= ord( $input[$i] ) << 16;
        $output.= self::$itoa64[ ( $value >> 12 ) & 0x3F ];
        if( $i++ >= $length ) break;
        $output.= self::$itoa64[ ( $value >> 18 ) & 0x3F ];
      }
      
      return $output;
      
    }
    
    /**
     * Generates salt.
     * 
     * @param string $input 
     * @return string
     */
    public static function genSalt( $input ) {
      
      $output = '$P$';
      $output.= self::$itoa64[ min( self::$iterations + 5, 30 ) ];
      $output.= self::encode64( $input, 6 );
      
      return $output;
      
    }
    
    /**
     * Generates salt for the extended hashing method.
     * 
     * @param string $input 
     * @return string
     */
    public static function genSaltExtended( $input ) {
      
      $log2 = min( self::$iterations + 8, 24 );
      // This should be odd to not reveal weak DES keys, and the
      // maximum valid value is (2**24 - 1) which is odd anyway.
      $count = ( 1 << $log2 ) - 1;
      
      $output = '_';
      $output.= self::$itoa64[ $count & 0x3F ];
      $output.= self::$itoa64[ ( $count >>  6 ) & 0x3F ];
      $output.= self::$itoa64[ ( $count >> 12 ) & 0x3F ];
      $output.= self::$itoa64[ ( $count >> 18 ) & 0x3F ];
      
      $output.= self::encode64( $input, 3 );
      
      return $output;
      
    }
    
    /**
     * Generates salt for the blowfish hashing method.
     * 
     * @param string $input 
     * @return string
     */
    public static function genSaltBlowfish( $input ) {
      // This one needs to use a different order of characters and a
      // different encoding scheme from the one in encode64() above.
      // We care because the last character in our encoded string will
      // only represent 2 bits.  While two known implementations of
      // bcrypt will happily accept and correct a salt string which
      // has the 4 unused bits set to non-zero, we do not want to take
      // chances and we also do not want to waste an additional byte
      // of entropy.
      $itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      
      $output = '$2a$';
      $output.= chr( ord( '0' ) + self::$iterations / 10 );
      $output.= chr( ord( '0' ) + self::$iterations % 10 );
      $output.= '$';
      
      $i = 0;
      
      while( 1 ) {
        
        $a = ord( $input[$i++] );
        $output.= $itoa64[ $a >> 2 ];
        $a = ( $a & 0x03 ) << 4;
        if( $i >= 16 ) {
          $output.= $itoa64[ $a ];
          break;
        }
        
        $b = ord( $input[$i++] );
        $a |= $b >> 4;
        $output.= $itoa64[ $a ];
        $a = ( $b & 0x0F ) << 2;
        
        $b = ord( $input[$i++] );
        $a |= $b >> 6;
        $output.= $itoa64[ $a ];
        $output.= $itoa64[ $b & 0x3F ];
        
      }
      
      return $output;
      
    }
    
    /**
     * Own crypt function, will be used if
     * neither blowfish nor DES are available.
     * 
     * @param string $password 
     * @param string $setting 
     * @return string
     */
    public static function crypt( $password, $setting ) {
      
      $output = '*0';
      
      if( substr( $setting, 0, 2 ) == $output )
        $output = '*1';
      
      $id = substr( $setting, 0, 3 );
      // We use $P$, phpBB3 uses "$H$" for the same thing
      if( $id != '$P$' && $id != '$H$' )
        return $output;
      
      $log2 = strpos( self::$itoa64, $setting[3] );
      if( $log2 < 7 || $log2 > 30 )
        return $output;
      
      $count = 1 << $log2;
      
      $salt = substr( $setting, 4, 8 );
      if( strlen( $salt ) !== 8 )
        return $output;
      
      // We're kind of forced to use MD5 here since it's the only
      // cryptographic primitive available in all versions of PHP
      // currently in use. To implement our own low-level crypto
      // in PHP would result in much worse performance and
      // consequently in lower iteration counts and hashes that are
      // quicker to crack (by non-PHP code).
      $hash = md5( $salt.$password, TRUE );
      
      while( $count-- )
        $hash = md5( $hash.password, TRUE );
      
      $output = substr( $setting, 0, 12 );
      $output.= self::encode64( $hash, 16 );
      
      return $output;
      
    }
    
  }
  
} ?>