<?php

// This is an example of the ViaThinkSoft AntiSpam 3.02
// for MarxCMS as filter plugin (modified $content)
// Use it for your website!

// CONFIGURATION

define('CFG_MAKE_MAIL_ADDRESSES_CLICKABLE', true);

// CODE

include '../v3.inc.php';

function secure_email_triv($email)
{
	if (!function_exists('alas_js_crypt'))
	{
		function alas_js_crypt($text)
		{
			$tmp = '';
			for ($i=0; $i<strlen($text); $i++)
			{
				$tmp .= 'document.write("&#'.ord(substr($text, $i, 1)).';");';
			}
			return $tmp;
		}
	}

	$aus = '';
	if ($email != '')
	{
		$aus .= '<script language="JavaScript" type="text/javascript"><!--'."\n";
		$aus .= alas_js_crypt($email);
		$aus .= '// --></script>';
	}
	return $aus;
}

function getAddrSpec() {
	// Ref: http://www.iamcal.com/publish/articles/php/parsing_email/

	$qtext = '[^\\x0d\\x22\\x5c\\x80-\\xff]';
	$dtext = '[^\\x0d\\x5b-\\x5d\\x80-\\xff]';
	$atom = '[^\\x00-\\x20\\x22\\x28\\x29\\x2c\\x2e\\x3a-\\x3c'.
		'\\x3e\\x40\\x5b-\\x5d\\x7f-\\xff]+';
	$quoted_pair = '\\x5c[\\x00-\\x7f]';
	$domain_literal = "\\x5b($dtext|$quoted_pair)*\\x5d";
	$quoted_string = "\\x22($qtext|$quoted_pair)*\\x22";
	$domain_ref = $atom;
	$sub_domain = "($domain_ref|$domain_literal)";
	$word = "($atom|$quoted_string)";
	$domain = "$sub_domain(\\x2e$sub_domain)*";
	$local_part = "$word(\\x2e$word)*";
	$addr_spec = "$local_part\\x40$domain";

	return $addr_spec;
}

function is_valid_email_address($email){
	$addr_spec = getAddrSpec();
	return preg_match("!^$addr_spec$!", $email) ? true : false;
}

function auto_secure_mail_addresses($content) {
	$addr_spec = getAddrSpec();

	// Step 1: Parse links and make them secure

	if (!function_exists('link_cb_1')) {
		function link_cb_1($a) {
			$mailaddr = $a[2];
			$linktext = $a[14]; // Letztes

			return secure_email($mailaddr, $linktext, is_valid_email_address($linktext));
		}
	}

	$content = preg_replace_callback("/<a(.+?)mailto:($addr_spec)(.+?)>(.+?)<\/a>/sm", 'link_cb_1', $content); // TODO! Kann Greedy werden!

	// Step 2: Find all further mail addresses, make then clickable and prevent spam bots

	if (!function_exists('link_cb_2')) {
		function link_cb_2($a) {
			$mailaddr = $a[1]; // Letztes

			if (CFG_MAKE_MAIL_ADDRESSES_CLICKABLE) {
				return secure_email($mailaddr, $mailaddr, true);
			} else {
				return secure_email_triv($mailaddr);
			}
		}
	}

	$content = preg_replace_callback("/($addr_spec)/sm", 'link_cb_2', $content);

	// Output

	return $content;
}

$content = auto_secure_mail_addresses($content);

?>
