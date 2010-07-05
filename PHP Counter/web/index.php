<?php

/*
 * PHP Counter mit Reloadsperre, Textdatenbank und Graphic-Libary (without Error Images)
 * (C) 2010 Daniel Marschall
 */

define('VERSION', '2010-07-05 20:05');

// Usage

// index.php            --> shows Counter PNG
// index.php?mode=blind --> only logs the visit and show only a PNG spacer
// index.php?mode=text  --> show text only

error_reporting(E_ALL | E_NOTICE);

$USER  = isset($_GET['user'])  ? $_GET['user']  : '';
$THEME = isset($_GET['theme']) ? $_GET['theme'] : '';
$MODE  = isset($_GET['mode'])  ? $_GET['mode']  : '';

$USER  = str_replace('.', '', $USER);
$THEME = str_replace('.', '', $THEME);

// Einstellungen

define('USER_DIR', 'data/'.$USER.'/');
define('THEME_DIR', 'themes/'.$THEME.'/');

define('COUNTER_FILE', USER_DIR.'counter.txt');
define('STELLEN', 6);

define('IP_FILE', USER_DIR.'ips.txt');
define('RELOADSPERRE_AKTIV', true);
define('RELOAD_MINUTES', 10);

define('DIGIT_PREFIX', THEME_DIR.'digit_');
define('DIGIT_SUFFIX', '.png');
define('BG_IMG', THEME_DIR.'bg.png');
define('SPACER', 'spacer.png');
define('SETTINGS', 'settings.inc.php');

// Beginn Programmcode

if ($USER == '') {
	echo '<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">';
	echo '<html>';
	echo '<head>';
	echo '<title>Counter by Daniel Marschall</title>';
	echo '<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">';
	echo '</head>';
	echo '<body>';
	echo '<h1>Counter by Daniel Marschall</h1>';
	echo '<p>Version '.VERSION.'</p>';
	echo '<h2>Usage</h2>';
	echo '<p><b>?user=[username]&amp;theme=[theme]</b> -- shows the graphic counter</p>';
	echo '<p><b>?user=[username]&amp;mode=text</b> -- shows the text counter</p>';
	echo '<p><b>?user=[username]&amp;mode=blind</b> -- shows a hidden spacer image</p>';
	echo '<h2>Available themes</h2>';
	echo '<ul>';
	foreach(glob('themes/*', GLOB_ONLYDIR) as $dir) {
		$dir = str_replace('themes/', '', $dir);
		echo '<li>'.$dir.'</li>';
	}
	echo '</ul>';
	echo '<h2>Available users</h2>';
	echo '<ul>';
	foreach(glob('data/*', GLOB_ONLYDIR) as $dir) {
		$dir = str_replace('data/', '', $dir);
		echo '<li>'.$dir.'</li>';
	}
	echo '</ul>';
	echo '<h2>Want a counter too?</h2>';
	echo '<p>Ask Daniel Marschall: info at daniel-marschall dot de.</p>';
	echo '</body>';
	echo '</html>';
	die();
}

if (!is_dir(USER_DIR)) {
	die('User "'.$USER.'" does not exist');
}

if (($MODE != 'blind') && ($MODE != 'text')) {
	if ((!is_dir(THEME_DIR)) || ($THEME == '')) {
		die('Theme "'.$THEME.'" does not exist');
	}
	if (file_exists(THEME_DIR.SETTINGS)) {
		include(THEME_DIR.SETTINGS);
	}
}

if (!file_exists(COUNTER_FILE)) {
	// Die Datei counter.txt existiert nicht, sie wird neu angelegt und mit dem Wert 0 gefüllt.
	$fp = fopen(COUNTER_FILE, 'w');
	$zahl = "0";
	fputs($fp, $zahl, STELLEN);
	fclose($fp);
}

if (!file_exists(IP_FILE)) {
	$fp = fopen(IP_FILE, 'w');
	fclose($fp);
}

function fetchip()
{
	// Source: http://lists.phpbar.de/pipermail/php/Week-of-Mon-20040322/007749.html

	$client_ip = (isset($_SERVER['HTTP_CLIENT_IP'])) ? $_SERVER['HTTP_CLIENT_IP'] : '';
	$x_forwarded_for = (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : '';
	$remote_addr = (isset($_SERVER['REMOTE_ADDR'])) ? $_SERVER['REMOTE_ADDR'] : '';

	if (!empty($client_ip))
	{
		$ip_expl = explode('.',$client_ip);
		$referer = explode('.',$remote_addr);
		if($referer[0] != $ip_expl[0])
		{
			$ip=array_reverse($ip_expl);
			$return=implode('.',$ip);
		}
		else
		{
			$return = $client_ip;
		}
	}
	else if (!empty($x_forwarded_for))
	{
		if(strstr($x_forwarded_for,','))
		{
			$ip_expl = explode(',',$x_forwarded_for);
			$return = end($ip_expl);
		}
	}
	else
	{
		$return = $remote_addr;
	}
	unset ($client_ip, $x_forwarded_for, $remote_addr, $ip_expl);
	return $return;
}

function isReloadLocked() {
	$rem_addr = fetchip();
	@$ip_array = file(IP_FILE);
	$reload_dat = fopen(IP_FILE, 'w');
	$this_time = time();
	$found = false;
	for ($i=0; $i<count($ip_array); $i++) {
		list($ip_addr, $time_stamp) = explode('|', $ip_array[$i]);
		if ($this_time < ($time_stamp + 60*RELOAD_MINUTES)) {
			if ($ip_addr == $rem_addr) {
				$found = true;
			} else {
				fwrite($reload_dat, "$ip_addr|$time_stamp");
			}
		}
	}
	fwrite($reload_dat, "$rem_addr|$this_time\n");
	fclose($reload_dat);
	return $found;
}

/////////////////////////////////////////
// Counter-Abfrage
/////////////////////////////////////////

function getCounter() {
	if ((!RELOADSPERRE_AKTIV) || (RELOADSPERRE_AKTIV && (!isReloadLocked()))) {
		// Es ist ein neuer Besucher
		$fp = fopen(COUNTER_FILE, 'r+');
		$zahl = fgets($fp, STELLEN);
		$zahl++;
		rewind($fp);
		flock($fp,2);
		fputs($fp, $zahl, STELLEN);
		flock($fp,3);
		fclose($fp);
	} else {
		// Es handelt sich wahrscheinlich um den gleichen Besucher
		$fp = fopen(COUNTER_FILE, 'r');
		$zahl = fgets($fp,STELLEN);
		fclose($fp);
	}

	$zahl = sprintf("%0".STELLEN."d", $zahl);

	return $zahl;
}

$counter = getCounter();

// No caching
header("HTTP/1.1 200 OK");
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

if ($MODE == 'blind') {
	header('Content-Type: image/png');

	readfile(SPACER);
} else if ($MODE == 'text') {
	header('Content-Type: text/plain');

	echo number_format ($counter, 0, ',', '.');
} else {
	header('Content-Type: image/png');

	$im = ImageCreateFromPNG (BG_IMG);
	imagesavealpha($im, true);

	$offset_x = DIGITS_X_OFFSET;
	$offset_y = DIGITS_Y_OFFSET;

	for ($i=0; $i<strlen($counter); $i++) {
		$digit_im = ImageCreateFromPNG(DIGIT_PREFIX.$counter[$i].DIGIT_SUFFIX);
		$digit_w = imagesx($digit_im);
		$digit_h = imagesy($digit_im);

		ImageCopy($im, $digit_im, $offset_x, $offset_y, 0, 0, $digit_w, $digit_h);
		ImageDestroy($digit_im);

		$offset_x += $digit_w + DIGITS_SPACER;
	}

	imagepng($im);
	imagedestroy($im);
}

?>