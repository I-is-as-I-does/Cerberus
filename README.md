# Cerberus

/!\ TESTS YET TO BE DONE. Not production ready.

A three-headed dog to set headers, and catch security reports, too.

## Install

```bash
composer require ssitu/cerberus
```

If you wish to use the `Catch` class, you will also require:

-> some Psr-3 logger  
-> and [SSITU/Blueprints](https://github.com/I-is-as-I-does/Blueprints)

- `FlexLogsTrait` and
- `FlexLogsInterface` specifically.

If no use of other SSITU blueprints, you can download just those two files.

## Overview

```php
use \SSITU\Cerberus\Cerberus;

require_once 'path/to/autoload.php';

$Cerberus = new Cerberus(array $whitelists = [], bool $reportOnly = false, bool $allowpost = false, array $features = []);
$Cerberus->setHeads(string $reportUri, array $allowedOrigins = []);

# to check if headers sent; returns bool
$Cerberus->headersSent();
```

`setHeads` _must_ be called before any kind of ouput.

### Samples

`__construct` arguments  
("should probably be static" config)

```php
# Please note that concerning whitelists, 'self' origin is always included
$whitelists = [
        'script' => [
            "https=>//tagmanager.google.com",
            "https=>//www.google-analytics.com",
            "https=>//www.gstatic.com",
            "https=>//ssl.gstatic.com",
            "https=>//www.googletagmanager.com",
            "https=>//*.googleapis.com",
            "https=>//cdn.jsdelivr.net",
            "https=>//cdnjs.cloudflare.com"],
        'style' => [],
        'font' => [
            "https=>//fonts.gstatic.com"],
        'img' => [
            "https=>//i.ytimg.com"],
        'media' => [
            "https=>//www.youtube-nocookie.com",
            "http=>//player.vimeo.com"],
        'connect' => [],
        'manifest' => [],
        'object' => [],
        'frame' => [],
        'default' => [],
        'worker' => [],
    ];

$reportonly = true; # for testing policies; should be set to false once in production
$allowpost => true; # to allow, or not, POST requests

# options: none, self, * (all), or space separated list of trusted origins
# defaults to none
$features = [
        "geolocation" => "*",
        "midi" => "none",
        "sync-xhr" => "none",
        "microphone" => "none",
        "camera" => "none",
        "magnetometer" => "none",
        "usb" => "none",
        "payment" => "none",
        "gyroscope" => "self",
        "accelerometer" => "https://acc-example.com",
        "encrypted-media" => "self https://encr-example.com https://another-example.com",
    ]
];
```

`setHeads` arguments  
("could be dynamically set" config)

```php
# Link to the controller that will record reports, log them, notify you, etc
$reportUri = 'https://my-own-website.com/report-controller';

# Cross-sites requests allowed origins:
$allowedOrigins = ['http://friendly-website-that-may-call-my-api.com', 'http://example-two.com'];
```

About `$allowedOrigins`:
Cerberus will check if one the trusted origins is requesting something, and if so, will allow it. Otherwise, nada.  
If you're not exchanging data with external sources, leave it empty.  
Setting it to `*` (allow all) is not an option here, because that's generally a pretty bad idea.

## Cerberus, Catch!

This an optional basic controller class, to catch reports.

```php
use \SSITU\Cerberus\CerberusCatch;

require_once 'path/to/autoload.php';

$CerberusCatch = new CerberusCatch();
$CerberusCatch->report();
```

Returns a boolean: true if there was indeed a security report to catch; false otherwise.
Report is logged.

### Log

```php
# optional:
$CerberusCatch->setLogger($somePsr3Logger);
# alternatively, you can retrieve logs that way:
$CerberusCatch->getLocalLogs();
// if no logger set: returns all logs history;
// else: only last entry
```

A logger can be set even after `report` method has been called.

## Contributing

Sure! You can take a loot at [CONTRIBUTING](CONTRIBUTING.md).

## License

This project is under the MIT License; cf. [LICENSE](LICENSE) for details.

![Doggo by William Blake](Cerberus-Blake.jpg)  
*William Blake*
