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
