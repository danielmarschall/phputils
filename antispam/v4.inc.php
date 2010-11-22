<?php

/*
 * ViaThinkSoft Anti-Spam Script for PHP
 * (C) 2009 ViaThinkSoft
 * Revision: 2009-07-11 (Version 4.0)
 */

function secure_email($email, $linktext, $crypt_linktext)
{
	// No new lines to avoid a JavaScript error!
	$linktext = str_replace("\r", ' ', $linktext);
	$linktext = str_replace("\n", ' ', $linktext);

	if (!defined('ALAS_INCLUDED')) {
		// Anfagswert über aktuelle Mikrosekunde setzen
		// http://de2.php.net/manual/de/function.srand.php
		function make_seed()
		{
			list($usec, $sec) = explode(' ', microtime());
			return (float) $sec + ((float) $usec * 100000);
		}
		srand(make_seed());

		define('ALAS_GARBARGE_LENGTH', 5);

		// http://www.jonasjohn.de/snippets/php/rand-str.htm
		function RandomString($len) {
			$randstr = '';
			srand((double)microtime()*1000000);
			for($i=0;$i<$len;$i++) {
				$n = rand(48,120);
				while (($n >= 58 && $n <= 64) || ($n >= 91 && $n <= 96)) {
					$n = rand(48,120);
				}
				$randstr .= chr($n);
			}
			return $randstr;
		}

		function js_randombreaks() {
			$len = rand(0, ALAS_GARBARGE_LENGTH);
			$r = '';
			$one_line_comment = false;
			for($i=0;$i<$len;$i++) {
				$m = rand(0, 3);
				if ($m == 0) {
					$r .= ' ';
				} else if ($m == 1) {
					$r .= '//';
					$r .= RandomString($i);
					$one_line_comment = true;
				} else if ($m == 2) {
					$r .= "\r\n";
					$one_line_comment = false;
				} else {
					$r .= "\t";
				}
			}
			if ($one_line_comment) $r .= "\r\n";
			return $r;
		}

		function alas_js_crypt($text) {
			$tmp = '';
			for ($i=0; $i<strlen($text); $i++) {
				$tmp .= js_randombreaks();
				$tmp .= 'document.write("&#'.ord(substr($text, $i, 1)).';");';
				$tmp .= js_randombreaks();
			}
			$tmp = js_randombreaks().$tmp.js_randombreaks();
			return $tmp;
		}

		function alas_noscript_crypt($text){
			$tmp = '';
			for ($i=0; $i<strlen($text); $i++) {
				$tmp .= '<span style="display:inline;">&#'.ord(substr($text, $i, 1)).';</span>';
				$tmp .= '<!--'.js_randombreaks().'-->';
				$tmp .= '<span style="display:none;">'.RandomString(rand(0, ALAS_GARBARGE_LENGTH)).'</span>';
			}
			return $tmp;
		}

		function alas_js_write($text) {
			$text = str_replace('\\', '\\\\', $text);
			$text = str_replace('"', '\"', $text);
			$text = str_replace('/', '\/', $text); // W3C Validation </a> -> <\/a>

			$ret  = '';
			$ret .= js_randombreaks();
			$ret .= 'document.write("'.$text.'");';
			$ret .= js_randombreaks();

			return $ret;
		}
	}

	define('ALAS_INCLUDED', true);

	$aus = '';
	if ($email != '')
	{
		$zid  = 'ALAS-4.0-'.DecHex(crc32($email)).'-'.DecHex(crc32($linktext)).'-'.($crypt_linktext ? 'S' : 'L');
		$title = 'ViaThinkSoft "ALAS" Anti-Spam';

		$aus .= "<!-- BEGIN $title [ID $zid] -->\r\n";
		$aus .= '<script language="JavaScript" type="text/javascript"><!--'."\n";
		$aus .= alas_js_write('<a href="');
		$aus .= alas_js_crypt('mailto:'.$email);
		$aus .= alas_js_write('">');
		$aus .= $crypt_linktext ? alas_js_crypt($linktext) : alas_js_write($linktext);
		$aus .= alas_js_write('</a>').'// --></script>';

		$aus .= '<noscript>';
		if ($linktext != $email) $aus .= ($crypt_linktext ? alas_noscript_crypt($linktext) : $linktext).' ';
		$aus .= alas_noscript_crypt("[ $email ]");
		$aus .= '</noscript>';
		$aus .= "\r\n<!-- END $title [ID $zid] -->\r\n";
	}

	return $aus;
}

function secure_email_autodetect($email, $linktext) {
	// Automatisch erkennen, ob der $linktext für Spambots interessant ist oder nicht
	$pos = strpos($linktext, '@');

	return secure_email($email, $linktext, $pos !== false);
}

function secure_email_identical_text($email) {
	return secure_email_autodetect($email, $email);
}

?>