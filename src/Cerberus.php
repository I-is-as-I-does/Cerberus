<?php
/* This file is part of Cerberus | SSITU | (c) 2021 I-is-as-I-does */
namespace SSITU\Cerberus;

class Cerberus
{
    private $whitelists;
    private $reportOnly;
    private $allowpost;
    private $features;

    private $reportUri;
    private $allowedOrigins;

    private $headSet = false;

    public function __construct(array $whitelists = [], bool $reportOnly = false, bool $allowpost = false, array $features = [])
    {
        $this->whitelists = $whitelists;
        $this->reportOnly = $reportOnly;
        $this->allowpost = $allowpost;
        $this->features = $features;
    }

    public function setHeads(string $reportUri, array $allowedOrigins = [])
    {
        if (!$this->headSets) {
            $this->allowedOrigins = $allowedOrigins; // @todo: if empty, should it fallback to at least self origin?
            $this->reportUri = $reportUri;

            $this->policies();
            $this->headSets = true;
        }
        return $this->headSets;
    }

    private function policies()
    {
        header("X-Frame-Options: sameorigin"); //@todo: should it be set to allow $http_origin?
        header("X-XSS-Protection: 1; mode=block");
        header("X-Content-Type-Options: nosniff");
        header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
        header("Referrer-Policy: no-referrer-when-downgrade");
        header("Connection: keep-alive");
        header_remove("X-Powered-By");
        header_remove("ETag");
        header($this->onDemandAllowedOrigin());
        header($this->allowMethods());
        header($this->contentSecurity());
        header($this->featurePolicy());

    }

    private function onDemandAllowedOrigin()
    {
        $allow = "null";
        if (!empty($this->allowedOrigins) && !empty($_SERVER['HTTP_ORIGIN']) && in_array($_SERVER['HTTP_ORIGIN'], $this->allowedOrigins)) {
            $allow = $_SERVER['HTTP_ORIGIN'];
        }
        return "Access-Control-Allow-Origin: $allow";
    }

    private function allowMethods()
    {

        $allow_methods = 'GET';
        if ($this->allowpost === true) {
            $allow_methods .= ' POST';
        }
        return "Access-Control-Allow-Methods: $allow_methods";

    }

    private function contentSecurity()
    {
        $content = 'Content-Security-Policy';
        if ($this->reportOnly === true) {
            $content .= '-Report-Only';
        }
        $content .= ": ";

        $sources = ['script', 'worker', 'connect','style', 'font', 'img', 'media', 'manifest', 'frame', 'object','default'];
        foreach ($sources as $src) {
            $whitelist = '';
            if (!empty($this->whitelists[$src])) {
                $whitelist = " '".implode("' '", $this->whitelist)."'";
            }
            $content .= "$src-src 'self'$whitelist; ";        
        }
        $content .= 'report-uri ' . $this->reporturi . ';';

        return $content;
    }

    private function featurePolicy()
    {

        $policies = [
            "geolocation" => "none",
            "midi" => "none",
            "sync-xhr" => "none",
            "microphone" => "none",
            "camera" => "none",
            "magnetometer" => "none",
            "usb" => "none",
            "payment" => "none",
            "gyroscope" => "none",
            "accelerometer" => "none",
            "encrypted-media" => "none",
        ];

        foreach ($policies as $feat => &$policy) {
            if (!empty($this->features[$feat]) && $this->features[$feat] != 'none') {
                $policy = $this->features[$feat];
                if(is_array($policy)){
                    $policy = explode(' ',$policy);
                    foreach($policy as $k=>$v){
                        if(empty($v) || in_array($v,['*','none'])){
                            unset($policy[$k]);
                        }
                    }
                    $policy = implode("' '",$policy);
                }
                if ($policy != '*') {
                    $policy = "'$policy'";
                }
            }
            $policy = $feat . ' ' . $policy;
        }
        $policies = implode('; ', $policies);

        return "Feature-Policy: $policies";
    }

}
