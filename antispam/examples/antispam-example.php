<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>

<head>
	<title>ViaThinkSoft AntiSpam Test</title>
</head>

<body>

<?php

echo '<form action="'.$PHP_SELF.'">
	E-Mail-Adresse: <input name="email" value="'.$_GET['email'].'"><br>
	Linktext: <input name="linktext" value="'.$_GET['linktext'].'"><br>
	Linktext verschlüsseln: <input type="checkbox" name="crypt_linktext" checked><br>
	V3 anstelle von V4 nutzen: <input type="checkbox" name="use_v3" checked><br>
	<input type="submit">
</form>';

if ($_GET['use_v3']) {
	include '../v3.inc.php';
} else {
	include '../v4.inc.php';
}

$x = secure_email($_GET['email'], $_GET['linktext'], isset($_GET['crypt_linktext']));
echo '<p>Implementierung:</p>';
echo '<textarea cols="120" rows="20">'.htmlentities($x).'</textarea>';
echo '<hr>';
echo '<p>Vorschau:</p>';
echo $x;

?>

</body>

</html>
