<?php
/* This file is part of Cerberus | SSITU | (c) 2021 I-is-as-I-does */
namespace SSITU\Cerberus;

class Cerberus
{
    private $whitelists;
    private $reportonly;
    private $allowpost;
    private $features;

    private $reportUri;
    private $allowedOrigins;

    private $headersSent = false;

    public function __construct(array $whitelists = [], bool $reportonly = false, bool $allowpost = false, array $features = [])
    {
        $this->whitelists = $whitelists;
        $this->reportonly = $reportonly;
        $this->allowpost = $allowpost;
        $this->features = $features;
    }

    public function headersSent()
    {
        return $this->headersSent;
    }

    public function setHeads(string $reportUri, array $allowedOrigins = [])
    {
        if (!$this->headersSent) {
            $this->allowedOrigins = $allowedOrigins; // @todo: if empty, should it fallback to at least self origin?
            $this->reportUri = $reportUri;

            $this->policies();
            $this->headersSent = true;
        }
        return $this->headersSent;
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
        if ($this->isAllowedOrigin()) {
            $allow = $_SERVER['HTTP_ORIGIN'];
        }
        return "Access-Control-Allow-Origin: $allow";
    }

    private function isAllowedOrigin()
    {
        if (!empty($this->allowedOrigins) && !empty($_SERVER['HTTP_ORIGIN'])) {
            if (in_array($_SERVER['HTTP_ORIGIN'], $this->allowedOrigins)) {
                return true;
            }
            foreach($this->allowedOrigins as $origin){
                if(stripos($origin, '*') !== false && fnmatch($origin, $_SERVER['HTTP_ORIGIN'])){
                    return true;
                }
            }
        }
        return false;
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
        if ($this->reportonly === true) {
            $content .= '-Report-Only';
        }
        $content .= ": ";

        $sources = ['script', 'worker', 'connect', 'style', 'font', 'img', 'media', 'manifest', 'frame', 'object', 'default'];
        foreach ($sources as $src) {
            $whitelist = '';
            if (!empty($this->whitelists[$src])) {
                $whitelist = implode(" ", $this->whitelists[$src]);
            }
            $content .= "$src-src 'self' $whitelist; ";
        }
        $content .= 'report-uri ' . $this->reportUri . ';';

        return $content;
    }

    private function featurePolicy()
    {

        $policies = [
            "geolocation" => "'none'",
            "midi" => "'none'",
            "sync-xhr" => "'none'",
            "microphone" => "'none'",
            "camera" => "'none'",
            "magnetometer" => "'none'",
            "usb" => "'none'",
            "payment" => "'none'",
            "gyroscope" => "'none'",
            "accelerometer" => "'none'",
            "encrypted-media" => "'none'",
        ];

        foreach ($policies as $feat => &$policy) {
            if (!empty($this->features[$feat]) && $this->features[$feat] != 'none') {
                $policy = $this->features[$feat];
                if (is_array($policy)) {
                    $policy = explode(' ', $policy);
                    foreach ($policy as $k => $v) {
                        if (empty($v) || in_array($v, ['*', 'none'])) {
                            unset($policy[$k]);
                        }
                    }
                    $policy = implode("' '", $policy);
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
