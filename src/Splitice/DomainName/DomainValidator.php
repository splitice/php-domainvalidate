<?php
namespace Splitice\DomainName;

/**
 * Validate for the existance of a domain name using DNS lookups and a whois lookup.
 *
 * Not 100% perfect, but fairly good.
 */
class DomainValidator
{
	function validate($domain_name)
	{
		$cmd = sprintf('whois -H %s', escapeshellarg($domain_name));
		$output = array();
		exec($cmd, $output);

		if (count($output) > 2)
			return true;

		$cmd = sprintf('dig %s NS', escapeshellarg($domain_name));
		$output = array();
		exec($cmd, $output);
		foreach ($output as $v) {
			if (strlen($v) == 0)
				continue;
			if ($v[0] == ';' && strpos($v, 'status: NOERROR')) {
				return true;
			}
		}

		$cmd = sprintf('dig %s NS | grep NS | grep %s', escapeshellarg($domain_name), escapeshellarg($domain_name));
		$output = array();
		exec($cmd, $output);

		foreach ($output as $k => $v) {
			if (strlen($v) == 0)
				continue;
			if ($v[0] == ';')
				unset($output[$k]);
		}

		if (count($output) >= 1)
			return true;

		return false;
	}
}