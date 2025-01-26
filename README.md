# TwoFactorAuth IP Whitelist Setup for Nextcloud

Description

This guide explains how to configure IP whitelisting for bypassing two-factor authentication (2FA) in Nextcloud. Users connecting from specified IP ranges will not be prompted for 2FA.

### 1. Log in via CLI to Your Nextcloud Container/VM
First, log in to your Nextcloud server using the command line. This could be either a Docker container or a VM running Nextcloud.

### 2. Edit the Manager.php File
Next, you'll need to modify the Nextcloud 2FA manager to check for whitelisted IPs. This will involve editing the file Manager.php.

Run the following command to open the file in a text editor (such as nano):
`sudo nano /var/www/nextcloud/lib/private/Authentication/TwoFactorAuth/Manager.php`

Once you have the file open, insert the provided code for IP matching in the appropriate place.

```
        /**
         * Determine whether the user must provide a second factor challenge
         */

		private function getClientIP(): string {
		        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		                $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
		                return trim($ipList[0]); // Pierwszy adres w nagłówku X-Forwarded-For to klient
		        }
		        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
		                return $_SERVER['HTTP_CLIENT_IP'];
		        }
		        return $_SERVER['REMOTE_ADDR']; // Domyślnie pobiera z REMOTE_ADDR
		}


        public function isTwoFactorAuthenticated(IUser $user): bool {
                // Check if IP is in whitelist
                if ($this->ipMatch()) {
                        return false; // Skip 2FA for whitelisted IPs
                }

                // Enforce mandatory 2FA if applicable
                if ($this->mandatoryTwoFactor->isEnforcedFor($user)) {
                        return true; // Force 2FA for users under mandatory policies
                }

                // Check available 2FA providers
                $providerStates = $this->providerRegistry->getProviderStates($user);
                $providers = $this->providerLoader->getProviders($user);
                $fixedStates = $this->fixMissingProviderStates($providerStates, $providers, $user);
                $enabled = array_filter($fixedStates);
                $providerIds = array_keys($enabled);
                $providerIdsWithoutBackupCodes = array_diff($providerIds, [self::BACKUP_CODES_PROVIDER_ID]);

                // Cache result for future calls
                $this->userIsTwoFactorAuthenticated[$user->getUID()] = !empty($providerIdsWithoutBackupCodes);
                return $this->userIsTwoFactorAuthenticated[$user->getUID()];
        }

        /**
         * Check if the user's IP address matches any of the whitelisted CIDRs
         *
         * @return bool
         */
			private function ipMatch(): bool {
			        $ip = $this->getClientIP();
			        $cidrs = $this->config->getSystemValue('twofactor_whitelist_ips', []);
			        foreach ((array) $cidrs as $cidr) {
			                list($subnet, $mask) = explode('/', $cidr);
			                $mask = ~((1 << (32 - $mask)) - 1); // Convert mask length to binary mask
			                if (((ip2long($ip) & $mask) == (ip2long($subnet) & $mask))) {
			                        return true; // IP is in the range
			                }
			        }
			        return false;
			}
```

### 3. Edit the config.php File
Next, you need to define the whitelisted IPs in Nextcloud's config.php file.

Run the following command to open the configuration file:
`sudo nano /var/www/nextcloud/config/config.php`

In the configuration file, add the whitelisted IPs under the twofactor_whitelist_ips key. For example:

```
  'twofactor_whitelist_ips' =>
  array (
    0 => '10.0.0.0/24',
  ),

```

### 4. Test the Setup

Now that you’ve made the changes, it’s time to test them.

First restart nextcloud and then try logging in from a whitelisted IP address. You should be able to log in without being prompted for 2FA.
Then test from a non-whitelisted IP address. You should still be asked to provide 2FA.

If everything works as expected, you've successfully configured IP whitelisting for 2FA in Nextcloud!


