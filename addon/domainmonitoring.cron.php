#!/usr/bin/php
<?php
/*
 * Title: DomainMonitoring plugin.
 * Version: 1.0.1 (10/Nov/2015)
 * Author: Denis.
 * License: GPL.
 * Site: https://montenegro-it.com
 * Email: contact@montenegro-it.com
 */
@set_time_limit(0);
@error_reporting(E_NONE);
@ini_set('display_errors', 0);
define("PLUGIN_PATH", "/usr/local/ispmgr/var/.plugin_domainmonitoring/");
include_once (PLUGIN_PATH."function.php");
DomainMonitoring::cron_run();