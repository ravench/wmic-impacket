<?php
/*
 * Observium compatibility harness for wmic-impacket.
 *
 * Reads wmic output on stdin, runs it through Observium's wmi_parse() (copied
 * verbatim from includes/wmi.inc.php, older version) and prints the result as
 * JSON.
 *
 *   php observium_wmi_parse.php [DELIMITER] [RET_SINGLE(0|1)] [RET_VAL]
 */

define('OBS_DEBUG', FALSE);

$GLOBALS['config']['wmi']['delimiter'] = (isset($argv[1]) && $argv[1] !== '') ? $argv[1] : '|';
$ret_single = isset($argv[2]) && $argv[2] === '1';
$ret_val    = (isset($argv[3]) && $argv[3] !== '') ? $argv[3] : NULL;

// ---- begin verbatim copy from Observium CE includes/wmi.inc.php -------------
// Source: https://github.com/pgmillon/observium/blob/master/includes/wmi.inc.php
// (C) 2006-2013 Adam Armstrong, (C) 2013-2016 Observium Limited
function wmi_parse($wmi_string, $ret_single = FALSE, $ret_val = NULL)
{
  $wmi_lines = array_filter(explode(PHP_EOL, $wmi_string), 'strlen');
  $wmi_class = NULL;
  $wmi_error = NULL;
  $wmi_properties = array();
  $wmi_results = array();

  foreach ($wmi_lines as $line)
  {
    if (preg_match('/ERROR:/', $line))
    {
      $wmi_error = substr($line, strpos($line, 'ERROR:') + strlen("ERROR: "));
      if (OBS_DEBUG)
      {
        // If the error is something other than "Retrieve result data." please report it
        switch($wmi_error) {
          case "Retrieve result data.":
            echo("WMI Error: Cannot connect to host or Class\n");
            break;
          case "Login to remote object.":
            echo("WMI Error: Invalid security credentials or insufficient WMI security permissions\n");
            break;
          default:
            echo("WMI Error: Please report");
            break;
        }
      }
      return NULL;
    }
    if (empty($wmi_class))
    {
      if (preg_match('/^CLASS:/', $line))
      {
        $wmi_class = substr($line, strlen("CLASS: "));
      }
    }
    else if (empty($wmi_properties))
    {
      $wmi_properties = explode($GLOBALS['config']['wmi']['delimiter'], $line);
    } else {
      $wmi_results[] = array_combine($wmi_properties, explode($GLOBALS['config']['wmi']['delimiter'], str_replace('(null)', '', $line)));
    }
  }

  if (count($wmi_results) == 1)
  {
    if ($ret_single)
    {
      if ($ret_val)
      {
        return $wmi_results[0][$ret_val];
      } else {
        return $wmi_results[0];
      }
    }
  }

  return $wmi_results;
}
// ---- end verbatim copy ------------------------------------------------------

$input  = stream_get_contents(STDIN);
$result = wmi_parse($input, $ret_single, $ret_val);
echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
echo PHP_EOL;
