<?php

if (!defined('SGM_ENGINE_USED')) die();

// PHP-AntiSpam-Funktion "secure_email", Version 3.03 of 2011-01-26
// von Daniel Marschall [www.daniel-marschall.de]

function secure_email($email, $linktext, $crypt_linktext, $css_class = '')
{
	// No new lines to avoid a JavaScript error!
	$linktext = str_replace("\r", ' ', $linktext);
	$linktext = str_replace("\n", ' ', $linktext);

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

	if (!function_exists('alas_js_write'))
	{
		function alas_js_write($text)
		{
			$text = str_replace('\\', '\\\\', $text);
			$text = str_replace('"', '\"', $text);
			$text = str_replace('/', '\/', $text); // W3C Validation </a> -> <\/a>
			return 'document.write("'.$text.'");';
		}
	}

	$aus = '';
	if ($email != '')
	{
		$aus .= '<script language="JavaScript" type="text/javascript"><!--'."\n";
		$aus .= alas_js_write('<a ');
		if ($css_class != '') $aus .= alas_js_write('class="'.$css_class.'" ');
		$aus .= alas_js_write('href="');
		$aus .= alas_js_crypt('mailto:'.$email);
		$aus .= alas_js_write('">');
		$aus .= $crypt_linktext ? alas_js_crypt($linktext) : alas_js_write($linktext);
		$aus .= alas_js_write('</a>').'// --></script>';
	}

	return $aus;
}

?>