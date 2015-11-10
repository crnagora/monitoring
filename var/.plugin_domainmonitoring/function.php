<?php

/*
 * Title: DomainMonitoring plugin.
 * Version: 1.0.0 (10/Nov/2015)
 * Author: Denis.
 * License: GPL.
 * Site: https://montenegro-it.com
 * Email: contact@montenegro-it.com
 */

class DomainMonitoring {

    static public function get_domainantizapret() {
        $blacklist = array();
        $domain = file("https://api.antizapret.info/group.php?data=domain&plugin=isp4", FILE_IGNORE_NEW_LINES);
        $server_domain = self::get_listdomain();
        $blacklist = array_intersect($domain, $server_domain);
        return $blacklist;
    }

    static public function get_ipantizapret() {
        $blacklist = array();
        $ip = file("https://api.antizapret.info/group.php?data=ip&plugin=isp4", FILE_IGNORE_NEW_LINES);
        $server_ip = self::get_serverip();
        $blacklist = array_intersect($ip, $server_ip);
        return $blacklist;
    }

    static public function check_block() {
        $data = array();
        $data['ip'] = self::get_ipantizapret();
        $data['domain'] = self::get_domainantizapret();
        return $data;
    }

    static public function get_spambase() {
        return array("zen.spamhaus.org", "cbl.abuseat.org", "bl.spamcop.net");
    }

    static public function send_mail($to, $from, $message) {
        foreach ($to as $mail) {
            $headers = array();
            $subject = "DomainMonitoring report";
            $headers[] = "MIME-Version: 1.0";
            $headers[] = "Content-type: text/plain; charset=utf-8";
            $headers[] = "From: " . $from . " <" . $from . ">";
            $headers[] = "Reply-To: " . $from . " <" . $from . ">";
            $headers[] = "Subject: {$subject}";
            mail($mail, $subject, $message, implode("\r\n", $headers));
            unset($headers);
        }
    }

    static public function cron_run() {
        $config = self::get_config();
        $message = "";
        if ($config['action']) {
            foreach (self::full_scan($config['action']) as $key => $row) {
                switch ($key) {
                    case "antizapret":
                        $message.="\n\nantizapret block is:\n";
                        foreach ($row['domain'] AS $item) {
                            $message.=$item . "\n";
                        }
                        foreach ($row['ip'] AS $item) {
                            $message.=$item . "\n";
                        }
                        break;
                    case "spam":
                        $message.="\n\nspam block is:\n";
                        foreach ($row['server'] AS $id => $item) {
                            $message.=$row['ip'][$id] . " on " . $item . "\n";
                        }
                        break;
                }
            }
            $hash = md5($message);
            if ($config['hash'] == $hash) {
                return;
            } else {
                self::send_mail($config['to'], $config['from'], $message);
                file_put_contents(PLUGIN_PATH . ".lock", $hash);
            }
        }
    }

    static public function save_setting($from, $email, $spam, $antizapret) {
        $tmp_email = explode(",", $email);
        $email_array = array();
        foreach ($tmp_email AS $row) {
            if (filter_var(trim($row), FILTER_VALIDATE_EMAIL)) {
                $email_array[] = trim($row);
            }
        }
        if (!filter_var($from, FILTER_VALIDATE_EMAIL)) {
            $from = "root@" . php_uname('n');
        }
        $data['from'] = $from;
        $data['email'] = $email_array;
        $data['spam'] = $spam;
        $data['antizapret'] = $antizapret;
        file_put_contents(PLUGIN_PATH . "setting.txt", json_encode($data));
        chmod(PLUGIN_PATH . "setting.txt", 0600);
    }

    static public function get_config() {
        $file = file_get_contents(PLUGIN_PATH . "setting.txt");
        if ($file) {
            $param = json_decode($file);

            $spam = 0;
            $antizapret = 0;
            if (property_exists($param->spam, 0)) {
                $spam = 1;
            }
            if (property_exists($param->antizapret, 0)) {
                $antizapret = 1;
            }
            if ($antizapret && $spam) {
                $data['action'] = 'both';
            } elseif ($antizapret && !$spam) {
                $data['action'] = 'antizapret';
            } elseif (!$antizapret && $spam) {
                $data['action'] = 'spam';
            } else {
                $data['action'] = 0;
            }
            $data['from'] = $param->from->{0};
            $data['to'] = $param->email;
            $data['hash'] = @file_get_contents(PLUGIN_PATH . ".lock");
        } else {
            $data['action'] = 0;
        }
        return $data;
    }

    static public function full_scan($type = 'none') {
        $data = array();
        switch ($type) {
            case "both":
                $antizapret = self::check_block();
                $data['antizapret']['ip'] = $antizapret['ip'];
                $data['antizapret']['domain'] = $antizapret['domain'];
                $data['spam'] = self::start_check();
                break;
            case "spam":
                $data['spam'] = self::start_check();
                break;
            case "antizapret":
                $antizapret = self::check_block();
                $data['antizapret']['ip'] = $antizapret['ip'];
                $data['antizapret']['domain'] = $antizapret['domain'];
                break;
            default:
        }
        return $data;
    }

    static public function start_check() {
        $ip = self::get_serverip();
        $data = self::check_base($ip);
        return self::filter_server($data);
    }

    static public function check_base($ip_array) {
        $data = array();
        ob_start();
        foreach ($ip_array as $row) {
            $revert = explode(".", $row);
            $ip = $revert[3] . "." . $revert[2] . "." . $revert[1] . "." . $revert[0];

            foreach (self::get_spambase() AS $base) {
                exec("host -tA " . $ip . "." . $base, $data['string']);
                $data['server'][] = $base;
                $data['ip'][] = $row;
            }
        }
        ob_end_clean();
        return $data;
    }

    static public function filter_server($server_array) {
        $search_string = "has address";
//for debug                 $search_string = "not found";
        $server = array();
        foreach ($server_array['string'] as $key => $row) {
            $pos = strpos($row, $search_string);
            if ($pos !== false) {
                $server['string'][] = $row;
                $server['ip'][] = $server_array['ip'][$key];
                $server['server'][] = $server_array['server'][$key];
            }
        }
        return $server;
    }

    static public function get_listdomain() {
        $Punycode = new Punycode();
        $domain = array();
        ob_start();
        exec("/usr/local/ispmgr/sbin/mgrctl -m ispmgr domain -o json", $data);
        ob_end_clean();
        $tmp = json_decode(implode("", $data));
        $list = $tmp->elem;
        foreach ($list as $row) {
            $domain[] = $Punycode->encode($row->name);
        }
        return $domain;
    }

    static public function get_serverip() {
        $data = array();
        ob_start();
        exec('ifconfig |grep -v lo | grep -v 127.0.0 | awk \'/flags/ {printf "Interface "$1" "} /inet/ {printf $2" "} /status/ {printf $2"\n"}\'|grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"', $data);
        $return = ob_get_contents();
        ob_end_clean();
        if ($return == 0) {
            //for debug   return array('8.8.8.8', '4.4.4.4', '66.44.11.99');
            return array_unique($data);
        } else {
            return false;
        }
    }

}

/*
 * https://github.com/true/php-punycode/
 * https://github.com/true/php-punycode/blob/master/LICENSE
 */

class Punycode {

    const BASE = 36;
    const TMIN = 1;
    const TMAX = 26;
    const SKEW = 38;
    const DAMP = 700;
    const INITIAL_BIAS = 72;
    const INITIAL_N = 128;
    const PREFIX = 'xn--';
    const DELIMITER = '-';

    protected static $encodeTable = array(
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
        'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    );
    protected static $decodeTable = array(
        'a' => 0, 'b' => 1, 'c' => 2, 'd' => 3, 'e' => 4, 'f' => 5,
        'g' => 6, 'h' => 7, 'i' => 8, 'j' => 9, 'k' => 10, 'l' => 11,
        'm' => 12, 'n' => 13, 'o' => 14, 'p' => 15, 'q' => 16, 'r' => 17,
        's' => 18, 't' => 19, 'u' => 20, 'v' => 21, 'w' => 22, 'x' => 23,
        'y' => 24, 'z' => 25, '0' => 26, '1' => 27, '2' => 28, '3' => 29,
        '4' => 30, '5' => 31, '6' => 32, '7' => 33, '8' => 34, '9' => 35
    );
    protected $encoding;

    public function __construct($encoding = 'UTF-8') {
        $this->encoding = $encoding;
    }

    public function encode($input) {
        $parts = explode('.', $input);
        foreach ($parts as &$part) {
            $part = $this->encodePart($part);
        }
        return implode('.', $parts);
    }

    protected function encodePart($input) {
        $codePoints = $this->listCodePoints($input);
        $n = static::INITIAL_N;
        $bias = static::INITIAL_BIAS;
        $delta = 0;
        $h = $b = count($codePoints['basic']);
        $output = '';
        foreach ($codePoints['basic'] as $code) {
            $output .= $this->codePointToChar($code);
        }
        if ($input === $output) {
            return $output;
        }
        if ($b > 0) {
            $output .= static::DELIMITER;
        }
        $codePoints['nonBasic'] = array_unique($codePoints['nonBasic']);
        sort($codePoints['nonBasic']);
        $i = 0;
        $length = mb_strlen($input, $this->encoding);
        while ($h < $length) {
            $m = $codePoints['nonBasic'][$i++];
            $delta = $delta + ($m - $n) * ($h + 1);
            $n = $m;
            foreach ($codePoints['all'] as $c) {
                if ($c < $n || $c < static::INITIAL_N) {
                    $delta++;
                }
                if ($c === $n) {
                    $q = $delta;
                    for ($k = static::BASE;
                    ; $k += static::BASE) {
                        $t = $this->calculateThreshold($k, $bias);
                        if ($q < $t) {
                            break;
                        }
                        $code = $t + (($q - $t) % (static::BASE - $t));
                        $output .= static::$encodeTable[$code];
                        $q = ($q - $t) / (static::BASE - $t);
                    }
                    $output .= static::$encodeTable[$q];
                    $bias = $this->adapt($delta, $h + 1, ($h === $b));
                    $delta = 0;
                    $h++;
                }
            }
            $delta++;
            $n++;
        }
        return static::PREFIX . $output;
    }

    public function decode($input) {
        $parts = explode('.', $input);
        foreach ($parts as &$part) {
            if (strpos($part, static::PREFIX) !== 0) {
                continue;
            }
            $part = substr($part, strlen(static::PREFIX));
            $part = $this->decodePart($part);
        }
        return implode('.', $parts);
    }

    protected function decodePart($input) {
        $n = static::INITIAL_N;
        $i = 0;
        $bias = static::INITIAL_BIAS;
        $output = '';
        $pos = strrpos($input, static::DELIMITER);
        if ($pos !== false) {
            $output = substr($input, 0, $pos++);
        } else {
            $pos = 0;
        }
        $outputLength = strlen($output);
        $inputLength = strlen($input);
        while ($pos < $inputLength) {
            $oldi = $i;
            $w = 1;
            for ($k = static::BASE;
            ; $k += static::BASE) {
                $digit = static::$decodeTable[$input[$pos++]];
                $i = $i + ($digit * $w);
                $t = $this->calculateThreshold($k, $bias);
                if ($digit < $t) {
                    break;
                }
                $w = $w * (static::BASE - $t);
            }
            $bias = $this->adapt($i - $oldi, ++$outputLength, ($oldi === 0));
            $n = $n + (int) ($i / $outputLength);
            $i = $i % ($outputLength);
            $output = mb_substr($output, 0, $i, $this->encoding) . $this->codePointToChar($n) . mb_substr($output, $i, $outputLength - 1, $this->encoding);
            $i++;
        }
        return $output;
    }

    protected function calculateThreshold($k, $bias) {
        if ($k <= $bias + static::TMIN) {
            return static::TMIN;
        } elseif ($k >= $bias + static::TMAX) {
            return static::TMAX;
        }
        return $k - $bias;
    }

    protected function adapt($delta, $numPoints, $firstTime) {
        $delta = (int) (
                ($firstTime) ? $delta / static::DAMP : $delta / 2
                );
        $delta += (int) ($delta / $numPoints);
        $k = 0;
        while ($delta > ((static::BASE - static::TMIN) * static::TMAX) / 2) {
            $delta = (int) ($delta / (static::BASE - static::TMIN));
            $k = $k + static::BASE;
        }
        $k = $k + (int) (((static::BASE - static::TMIN + 1) * $delta) / ($delta + static::SKEW));
        return $k;
    }

    protected function listCodePoints($input) {
        $codePoints = array(
            'all' => array(),
            'basic' => array(),
            'nonBasic' => array(),
        );
        $length = mb_strlen($input, $this->encoding);
        for ($i = 0; $i < $length; $i++) {
            $char = mb_substr($input, $i, 1, $this->encoding);
            $code = $this->charToCodePoint($char);
            if ($code < 128) {
                $codePoints['all'][] = $codePoints['basic'][] = $code;
            } else {
                $codePoints['all'][] = $codePoints['nonBasic'][] = $code;
            }
        }
        return $codePoints;
    }

    protected function charToCodePoint($char) {
        $code = ord($char[0]);
        if ($code < 128) {
            return $code;
        } elseif ($code < 224) {
            return (($code - 192) * 64) + (ord($char[1]) - 128);
        } elseif ($code < 240) {
            return (($code - 224) * 4096) + ((ord($char[1]) - 128) * 64) + (ord($char[2]) - 128);
        } else {
            return (($code - 240) * 262144) + ((ord($char[1]) - 128) * 4096) + ((ord($char[2]) - 128) * 64) + (ord($char[3]) - 128);
        }
    }

    protected function codePointToChar($code) {
        if ($code <= 0x7F) {
            return chr($code);
        } elseif ($code <= 0x7FF) {
            return chr(($code >> 6) + 192) . chr(($code & 63) + 128);
        } elseif ($code <= 0xFFFF) {
            return chr(($code >> 12) + 224) . chr((($code >> 6) & 63) + 128) . chr(($code & 63) + 128);
        } else {
            return chr(($code >> 18) + 240) . chr((($code >> 12) & 63) + 128) . chr((($code >> 6) & 63) + 128) . chr(($code & 63) + 128);
        }
    }

}
