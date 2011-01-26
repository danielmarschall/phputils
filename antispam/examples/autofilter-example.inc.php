<?php

// ========================================================================

// SOURCE: SIGMA 3.0 ANTISPAM CONFIG

define('CFG_MAKE_MAIL_ADDRESSES_CLICKABLE', true);
define('CFG_CORRET_MISSING_MAILTO', true);
define('CFG_DEFAULT_CLASS', 'mail-addr');

// ========================================================================

// SOURCE: SIGMA 3.0 ANTISPAM FILTER

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
	$atom = '[^\\x00-\\x20\\x22\\x28\\x29\\x2c\\x2e\\x3a-\\x3c\\x3e\\x40\\x5b-\\x5d\\x7f-\\xff]+';
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

function is_valid_email_address($email) {
	// TODO: Hier lieber einen korrekten Mailvalidator verwenden (C.Sayers Lösung)?

	$ary = explode('?', $email);
	$email = $ary[0];

	$addr_spec = getAddrSpec();
	return preg_match("!^$addr_spec$!", $email);
}

class MailLinkProtector extends UrlParseIterator {
	var $correct_missing_mailto;

	protected function link_callback($complete, $pre, $post, $urltype, $bracket, $url, $linktext) {
		if (beginsWithI($url, 'mailto:')) {
			// Link ist eine Mailadresse
			$mailaddr = remove_beginning_i($url, 'mailto:');
			return secure_email($mailaddr, $linktext, is_valid_email_address($linktext), CFG_DEFAULT_CLASS);
		} else if (($this->correct_missing_mailto) && (is_valid_email_address($url))) {
			// Hier hat jemand "mailto:" vergessen. Wir korrigieren das mal...
			$mailaddr = $url;
			return secure_email($mailaddr, $linktext, is_valid_email_address($linktext), CFG_DEFAULT_CLASS);
		} else {
			// Normaler Link
			return $complete;
		}
	}
}

function link_cb_2($a) {
	$mailaddr = $a[1]; // Letztes

	if (CFG_MAKE_MAIL_ADDRESSES_CLICKABLE) {
		return secure_email($mailaddr, $mailaddr, true, CFG_DEFAULT_CLASS);
	} else {
		return secure_email_triv($mailaddr);
	}
}

function protect_mail_address_urls($content, $correct_missing_mailto = true) {
	$t = new MailLinkProtector;
	$t->correct_missing_mailto = $correct_missing_mailto;
	return $t->process($content);
}

function auto_secure_mail_addresses($content) {
	// Step 1: Parse links and make them secure

	$content = protect_mail_address_urls($content, CFG_CORRET_MISSING_MAILTO);

	// Step 2: Find all further mail addresses, make then clickable and prevent spam bots

	$addr_spec = getAddrSpec();

	// This fixes an error if the file is unix converted...
	// The error occoured at server4.configcenter.info:
	// [Fri Mar 26 20:23:24 2010] [error] [client 87.165.172.145] (104)Connection reset by peer: FastCGI: comm with server "/home/www/web66/html/cgi-bin/php-fcgi-starter" aborted: read failed
	// [Fri Mar 26 20:23:24 2010] [error] [client 87.165.172.145] FastCGI: incomplete headers (0 bytes) received from server "/home/www/web66/html/cgi-bin/php-fcgi-starter"
	$content = str_replace("\n", "\r\n", $content);

	// Diese Zeichen ausschließen, damit z.B. Satzzeichen am Ende einer E-Mail-Adresse, Anführungszeichen oder Klammern nicht
	// als Teil der Adresse angesehen werden. Die Liste ist länger als $addr_spec eigentlich benötigt (z.B. schließt $addr_spec
	// einen Punkt am Ende automatisch aus). Aber sicher ist sicher.
	$exclude_mail_chars_beginning = '\^°!"§$%&/()=\?´`}\]\[{\+*~\'#-_\.:,;';
	$exclude_mail_chars_ending = $exclude_mail_chars_beginning;

	$content = preg_replace_callback("@(?![$exclude_mail_chars_beginning])($addr_spec)(?<![$exclude_mail_chars_ending])@sm", 'link_cb_2', $content);

	// Output

	return $content;
}

// ========================================================================

// SOURCE: SIGMA 3.0 _sigma.php

class UrlParseIterator {
	var $use_original_bracket_at_link = false;
	var $use_original_bracket_at_css = false;
	var $use_original_bracket_at_other = false;

	protected function process_url($url) {
		// Overwrite this method in a derivate!
		return $url;
	}

	// LINK

	private function link_style_regex() {
		return "@(<a\s[^>]*(href)\s*=\s*)(?(?=[\"'])(([\"'])([^>]*)\\4)|()([^ >]*?))([^>]*>)(.*)</a>@ismU";
	}

	protected function link_callback($complete, $pre, $post, $urltype, $bracket, $url, $linktext) {
		$url = $this->process_url($url);

		return $pre.$bracket.$url.$bracket.$post.$linktext.'</a>';
	}

	private function link_first_callback($c) {
		$complete = $c[0];

		$pre = $c[1];
		$post = $c[8];

		$urltype = $c[2]; // = href

		if ($this->use_original_bracket_at_link) {
			$bracket = $c[4];
		} else {
			$bracket = '"';
		}

		$url = $c[5].$c[7]; // Either [5] OR [7] is filled, so I simply concat them.

		$linktext = $c[9];

		return $this->link_callback($complete, $pre, $post, $urltype, $bracket, $url, $linktext);
	}

	// CSS

	private function css_style_regex() {
		return "/url\(\s*(?(?=[\"'])(([\"'])([^>]*)\\2)|([^\)]*?))\)/isUm";
	}

	protected function css_callback($complete, $bracket, $url) {
		$url = $this->process_url($url);

		return 'url('.$bracket.$url.$bracket.')';
	}

	private function css_first_callback($c) {
		$complete = $c[0];

		if ($this->use_original_bracket_at_css) {
			$bracket = $c[2];
		} else {
			$bracket = "'";
		}

		if (!isset($c[4])) $c[4] = '';
		$url = $c[3].$c[4]; // Either [3] OR [4] is filled, so I simply concat them.

		return $this->css_callback($complete, $bracket, $url);
	}

	// Other (does not include a-href, but base-href etc.)

	private function other_style_regex() {
		return "/((<(?!a\s)[^><]*)(href)|src|background|code)\s*=\s*(?(?=[\"'])(([\"'])([^>]*)\\5)|([^ >]*?))/isUm";
	}

	protected function other_callback($complete, $bracket, $type, $url) {
		$url = $this->process_url($url);

		return $type.'='.$bracket.$url.$bracket;
	}

	private function other_first_callback($c) {
		// Aufgrund des regex ist bei einem href $c[0] nicht href="..." sondern <base ... href="..."
		// Wir verdecken diesen zusätzlichen Anfang, leiten ihn an die abstrakte callback-Funktion weiter
		// und fügen später beim zurückliefern diesen Präfix $pre wieder hinzu.
		$pre = $c[2];

		$complete = remove_beginning($c[0], $pre);

		if ($c[3] == '') {
			$type = $c[1];
		} else {
			$type = $c[3];
		}

		if ($this->use_original_bracket_at_other) {
			$bracket = $c[5];
		} else {
			$bracket = '"';
		}

		if (!isset($c[7])) $c[7] = '';
		$url = $c[6].$c[7]; // Either [6] OR [7] is filled, so I simply concat them.

		return $pre.$this->other_callback($complete, $bracket, $type, $url);
	}

	// Processing functions

	private function process_links($content) {
		$r = preg_replace_callback($this->link_style_regex(), array(&$this, 'link_first_callback'), $content);
		if ($r == null) return $content; // z.B. bei doppeltem ALAS-Processing!
		return $r;
	}

	private function process_other($content) {
		$r = preg_replace_callback($this->other_style_regex(), array(&$this, 'other_first_callback'), $content);
		if ($r == null) return $content;
		return $r;
	}

	private function process_css($content) {
		$r = preg_replace_callback($this->css_style_regex(), array(&$this, 'css_first_callback'), $content);
		if ($r == null) return $content;
		return $r;
	}

	public function process($content) {
		$content = $this->process_links($content);
		$content = $this->process_other($content);
		$content = $this->process_css($content);

		return $content;
	}
}

// ========================================================================

// SOURCE: VIATHINKSOFT ANTI SPAM

include '../v3.inc.php';

// ========================================================================

// SOURCE: SIGMA 3.0 _sigma.php

function remove_beginning($content, $beginning) {
	if (beginsWith($content, $beginning)) {
		return substr($content, strlen($beginning), strlen($content)-strlen($beginning));
	} else {
		return $content;
	}
}

function beginsWithI($content, $beginning) {
	return beginsWith(strtolower($content), strtolower($beginning));
}

function beginsWith($content, $beginning) {
	// return substr($content, 0, strlen($beginning)) == $beginning;
	return (strncmp($content, $beginning, strlen($beginning)) == 0);
}

function remove_beginning_i($content, $beginning) {
	if (beginsWithI($content, $beginning)) {
		return substr($content, strlen($beginning), strlen($content)-strlen($beginning));
	} else {
		return $content;
	}
}

// ========================================================================

// USAGE:
// $content = auto_secure_mail_addresses($content);

// ========================================================================

?>
