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
               $doc->addChild("ok", "ok");
            break;
           }
          
          break;
    
}
echo $doc->asXML();