<?php
/* This file is part of Cerberus | SSITU | (c) 2021 I-is-as-I-does */
namespace SSITU\Cerberus;

class CerberusCatch implements \SSITU\Blueprints\FlexLogsInterface
{

    use Blueprints\FlexLogsTrait;

    public function report()
    {
        // @doc: Get the raw POST data.
        $catchd = file_get_contents('php://input');

        // @doc: Only continue if it’s valid JSON that is not just 'null', '0', 'false'
        // or an empty string, i.e. if it could be a CSP violation report.
        if ($catchd_arr = json_decode($catchd,true) && isset($catchd_arr["csp-report"])) {

            $catchd_details = [];
            $catchd_its = $catchd_arr["csp-report"];
            foreach ($catchd_its as $catchd_title => $catchd_it) {
                if ($catchd_title == "original-policy") {
                    $catchd_it .= " | cf. Cerberus policies";
                }
                if ($catchd_it != "") {
                    $catchd_details[$catchd_title] = $catchd_it;
                }
            }
            $this->log('warning','csp-report', $catchd_details);
            return true;
        }
        $this->log('notice', 'csp-false-alarm');
        return false;
    }
}
