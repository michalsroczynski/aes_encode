<?php

/**
* 
*/
class EncodeAes256CBCPkcs5
{
    protected $textToEncode;
    protected $key;
    
    function __construct($textToEncode, $key)
    {
        $this->textToEncode = $textToEncode;
        $this->key = $key;
    }

    public function encode()
    {
        $iv = $this->iv();
        $encryptedText =  mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->keyConvert(), $this->pkcs5($this->textToEncode), MCRYPT_MODE_CBC, $iv);
        $encryptedText = ($iv.$encryptedText);
        return $encryptedText;
    }

    public function urlEncode($encryptedText)
    {
        return urlencode(base64_encode($encryptedText));
    }

    private function keyConvert()
    {
        return pack('H*', $this->key);
    }

    private function pkcs5($text)
    {
        $mcryptBlocksize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $padding = $mcryptBlocksize - (strlen($text) % $mcryptBlocksize);
        return $text . str_repeat(chr($padding), $padding);
    }

    private function iv()
    {
        $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        return $iv;
    }

}

?>
