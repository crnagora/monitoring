#!/usr/bin/php
<?php
/*
 * Title: DomainMonitoring plugin.
 * Version: 1.0.0 (10/Nov/2015)
 * Author: Denis.
 * License: GPL.
 * Site: https://montenegro-it.com
 * Email: contact@montenegro-it.com
 */
@set_time_limit(0);
@error_reporting(E_NONE);
@ini_set('display_errors', 0);
$xml_string = file_get_contents("php://stdin");
$doc = simplexml_load_string($xml_string);
$func = $doc->params->func;
$sok = $doc->params->sok;
$elid = $doc->params->elid;
$user = $doc["user"];
$level = $doc["level"];
define("PLUGIN_PATH", "/usr/local/ispmgr/var/.plugin_domainmonitoring/");
include_once (PLUGIN_PATH . "function.php");

switch ($func) {
    case "domainmonitoring.setting";
        if ($sok == "ok") {
            DomainMonitoring::save_setting($doc->params->from, $doc->params->email, $doc->params->spam, $doc->params->antizapret);
            $doc->addChild("ok", "ok");
            break;
        }

        if (is_file(PLUGIN_PATH . "setting.txt")) {
            $data = json_decode(file_get_contents(PLUGIN_PATH . "setting.txt"));
            $email = implode(", ", $data->email);
            $from = $data->from->{0};
            $spam = $data->spam->{0};
            $antizapret = $data->antizapret->{0};
        } else {
            $spam = "";
            $antizapret = "";
            $email = "";
            $from = "";
        }

        $doc->addChild("email", $email);
        $doc->addChild("from", $from);
        if ($spam) {
            $doc->addChild("spam", $spam);
        }
        if ($antizapret) {
            $doc->addChild("antizapret", $antizapret);
        }
        
        break;
}
echo $doc->asXML();
