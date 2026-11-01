<?php
/*
 * Runs the wmi_parse() of an installed Observium on wmic output from stdin and
 * prints the result as JSON.  Nothing from Observium is copied here: the
 * function is loaded from $OBSERVIUM_DIR/includes/wmi.inc.php at run time, with
 * minimal stand-ins for the few Observium helpers it calls.
 *
 *   OBSERVIUM_DIR=/opt/observium php observium_current_parse.php [DELIMITER] [RET_SINGLE(0|1)]
 */

$dir = getenv('OBSERVIUM_DIR');
if ($dir === FALSE || !is_file($dir . '/includes/wmi.inc.php')) {
    fwrite(STDERR, "OBSERVIUM_DIR must point to an Observium install\n");
    exit(2);
}

define('OBS_DEBUG', 0);
$GLOBALS['config']['wmi']['delimiter'] = (isset($argv[1]) && $argv[1] !== '') ? $argv[1] : '##';
$ret_single = isset($argv[2]) && $argv[2] === '1';

// Stand-ins for Observium helpers used by wmi_parse().
if (!function_exists('safe_empty')) {
    function safe_empty($value) { return $value === NULL || $value === '' || $value === []; }
}
if (!function_exists('str_starts')) {
    function str_starts($haystack, $needle) { return strncmp((string)$haystack, (string)$needle, strlen((string)$needle)) === 0; }
}
if (!function_exists('str_contains')) { // PHP < 8
    function str_contains($haystack, $needle) { return $needle === '' || strpos((string)$haystack, (string)$needle) !== FALSE; }
}
if (!function_exists('print_debug'))      { function print_debug($text) {} }
if (!function_exists('print_debug_vars')) { function print_debug_vars($vars) {} }
if (!function_exists('print_error'))      { function print_error($text) { fwrite(STDERR, "print_error: $text\n"); } }

require $dir . '/includes/wmi.inc.php';

$result = wmi_parse(stream_get_contents(STDIN), $ret_single);
echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), PHP_EOL;
