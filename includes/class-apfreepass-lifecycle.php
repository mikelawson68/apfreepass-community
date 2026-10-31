<?php
/**
 * apFreepass lifecycle service.
 *
 * @package apFreepass
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('APFreepass_Lifecycle')) {
    final class APFreepass_Lifecycle
    {
        /**
         * @param array<string,mixed> $data
         * @return array<string,mixed>
         */
        public static function create_method_policy(array $data): array
        {
            global $wpdb;

            $tables = APFreepass_Schema::tables();
            $rp_id = self::nullable_text($data['rp_id'] ?? null) ?: self::default_rp_id();
            $inserted = $wpdb->insert(
                $tables['method_policy'],
                [
                    'scope_type' => self::allowed((string) ($data['scope_type'] ?? 'site'), ['site', 'network', 'role'], 'site'),
                    'scope_id' => absint($data['scope_id'] ?? 0),
                    'magic_link_enabled' => array_key_exists('magic_link_enabled', $data) && empty($data['magic_link_enabled']) ? 0 : 1,
                    'sms_enabled' => !empty($data['sms_enabled']) ? 1 : 0,
                    'passkey_enabled' => !empty($data['passkey_enabled']) ? 1 : 0,
                    'allowed_roles_json' => self::json($data['allowed_roles'] ?? ['administrator']),
                    'rp_id' => $rp_id,
                    'sms_provider_ref' => self::nullable_text($data['sms_provider_ref'] ?? null),
                    'crm_resolver_enabled' => !empty($data['crm_resolver_enabled']) ? 1 : 0,
                    'status' => 'active',
                    'created_at' => self::now(),
                    'updated_at' => self::now(),
                ],
                ['%s', '%d', '%d', '%d', '%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s']
            );

            if (!$inserted) {
                return self::error('method_policy_insert_failed', 'Could not create passwordless method policy.');
            }

            return ['success' => true, 'method_policy_id' => (int) $wpdb->insert_id, 'rp_id' => $rp_id];
        }

        /**
         * @return array<string,mixed>
         */
        public static function issue_magic_link(int $user_id, string $email, string $redirect_url = ''): array
        {
            global $wpdb;

            $tables = APFreepass_Schema::tables();
            $token = bin2hex(random_bytes(32));
            $inserted = $wpdb->insert(
                $tables['magic_links'],
                [
                    'user_id' => $user_id,
                    'email' => sanitize_email($email),
                    'token_hash' => self::hash_secret($token),
                    'redirect_url' => self::nullable_url($redirect_url),
                    'status' => 'issued',
                    'expires_at' => self::expires_in(15 * MINUTE_IN_SECONDS),
                    'created_at' => self::now(),
                    'updated_at' => self::now(),
                ],
                ['%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
            );

            if (!$inserted) {
                return self::error('magic_link_insert_failed', 'Could not issue magic link.');
            }

            $magic_link_id = (int) $wpdb->insert_id;
            self::audit($user_id, 'magic_link', 'success', 'issued', ['delivery' => 'email_connector_or_wp_mail']);
            return ['success' => true, 'magic_link_id' => $magic_link_id, 'token' => $token];
        }

        /**
         * @return array<string,mixed>
         */
        public static function verify_magic_link(string $token): array
        {
            global $wpdb;

            $tables = APFreepass_Schema::tables();
            $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM %i WHERE token_hash = %s", $tables['magic_links'], self::hash_secret($token)));
            if (!$row) {
                return self::error('magic_link_not_found', 'Magic link was not found.');
            }
            if (!in_array((string) $row->status, ['issued', 'sent'], true) || self::is_expired((string) $row->expires_at)) {
                self::audit((int) $row->user_id, 'magic_link', 'expired', 'expired_or_used');
                return self::error('magic_link_expired', 'Magic link is expired or already used.');
            }

            // Atomically consume the token: only one simultaneous request can win.
            $now = self::now();
            $updated = $wpdb->query($wpdb->prepare(
                "UPDATE %i SET status = 'verified', used_at = %s, updated_at = %s WHERE id = %d AND status IN ('issued', 'sent') AND expires_at > %s",
                $tables['magic_links'], $now, $now, (int) $row->id, $now
            ));
            if ($updated !== 1) {
                return self::error('magic_link_expired', 'Magic link is expired or already used.');
            }
            self::audit((int) $row->user_id, 'magic_link', 'success', 'verified');

            return ['success' => true, 'user_id' => (int) $row->user_id, 'magic_link_id' => (int) $row->id];
        }

        /**
         * @return array<string,mixed>
         */
        public static function issue_sms_challenge(int $user_id, string $phone_e164, string $provider_ref = ''): array
        {
            global $wpdb;
            if ($user_id < 1) return self::error('invalid_user', 'A valid user is required.');
            $lock = 'apfreepass_sms_' . substr(hash('sha256', $wpdb->prefix . ':' . $user_id), 0, 40);
            if ((string) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', $lock)) !== '1') {
                return self::error('rate_limited', 'Please wait before requesting another code.');
            }
            try {
                return self::issue_sms_challenge_locked($user_id, $phone_e164, $provider_ref);
            } finally {
                $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
            }
        }

        private static function issue_sms_challenge_locked(int $user_id, string $phone_e164, string $provider_ref): array
        {
            global $wpdb;
            $tables = APFreepass_Schema::tables();
            // Count all outcomes, including failed deliveries, to bound retries.
            $recent = $wpdb->get_var($wpdb->prepare(
                'SELECT COUNT(*) FROM %i WHERE user_id = %d AND created_at > %s',
                $tables['sms_challenges'], $user_id, gmdate('Y-m-d H:i:s', time() - 15 * MINUTE_IN_SECONDS)
            ));
            if ($recent === null || (int) $recent >= 3) {
                return self::error('rate_limited', 'Please wait before requesting another code.');
            }
            $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
            $inserted = $wpdb->insert(
                $tables['sms_challenges'],
                [
                    'user_id' => $user_id,
                    'phone_e164' => self::normalize_phone($phone_e164) ?: $phone_e164,
                    'code_hash' => self::hash_secret($code),
                    'provider_ref' => self::nullable_text($provider_ref),
                    'delivery_request_ref' => 'planned:apsms:' . bin2hex(random_bytes(6)),
                    'status' => 'issued',
                    'attempts' => 0,
                    'expires_at' => self::expires_in(10 * MINUTE_IN_SECONDS),
                    'created_at' => self::now(),
                    'updated_at' => self::now(),
                ],
                ['%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s']
            );

            if (!$inserted) {
                return self::error('sms_challenge_insert_failed', 'Could not issue SMS challenge.');
            }

            $sms_challenge_id = (int) $wpdb->insert_id;
            self::audit($user_id, 'sms_code', 'success', 'issued', ['provider_ref' => $provider_ref ?: 'shared_apsms_provider_registry']);
            return ['success' => true, 'sms_challenge_id' => $sms_challenge_id, 'code' => $code];
        }

        /**
         * @return array<string,mixed>
         */
        public static function verify_sms_challenge(int $challenge_id, string $code): array
        {
            global $wpdb;

            $tables = APFreepass_Schema::tables();
            $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM %i WHERE id = %d", $tables['sms_challenges'], $challenge_id));
            if (!$row) {
                return self::error('sms_challenge_not_found', 'SMS challenge was not found.');
            }
            if (!in_array((string) $row->status, ['issued', 'sent'], true) || self::is_expired((string) $row->expires_at)) {
                self::audit((int) $row->user_id, 'sms_code', 'expired', 'expired_or_used');
                return self::error('sms_challenge_expired', 'SMS challenge is expired or already used.');
            }
            if ((int) $row->attempts >= 5) {
                self::audit((int) $row->user_id, 'sms_code', 'denied', 'too_many_attempts');
                return self::error('sms_challenge_locked', 'Too many attempts.');
            }
            if (!hash_equals((string) $row->code_hash, self::hash_secret($code))) {
                // Count failures atomically so concurrent guesses cannot evade the limit.
                $now = self::now();
                $updated = $wpdb->query($wpdb->prepare(
                    "UPDATE %i SET attempts = attempts + 1, updated_at = %s WHERE id = %d AND status IN ('issued', 'sent') AND attempts < 5 AND expires_at > %s",
                    $tables['sms_challenges'], $now, $challenge_id, $now
                ));
                if ($updated !== 1) return self::error('sms_challenge_locked', 'This challenge is expired, used, or has too many attempts.');
                self::audit((int) $row->user_id, 'sms_code', 'failure', 'invalid_code');
                return self::error('sms_code_invalid', 'Invalid SMS code.');
            }

            $now = self::now();
            $updated = $wpdb->query($wpdb->prepare(
                "UPDATE %i SET status = 'verified', verified_at = %s, updated_at = %s WHERE id = %d AND status IN ('issued', 'sent') AND attempts < 5 AND expires_at > %s AND code_hash = %s",
                $tables['sms_challenges'], $now, $now, $challenge_id, $now, (string) $row->code_hash
            ));
            if ($updated !== 1) return self::error('sms_challenge_locked', 'This challenge is expired, used, or has too many attempts.');
            self::audit((int) $row->user_id, 'sms_code', 'success', 'verified');

            return ['success' => true, 'user_id' => (int) $row->user_id, 'sms_challenge_id' => $challenge_id];
        }

        /**
         * @param array<string,mixed> $data
         * @return array<string,mixed>
         */
        public static function register_passkey_credential(int $user_id, array $data): array
        {
            global $wpdb;

            $tables = APFreepass_Schema::tables();
            $credential_id = self::nullable_text($data['credential_id'] ?? null);
            if (!$credential_id) {
                return self::error('credential_id_required', 'Credential ID is required.');
            }
            $rp_id = self::nullable_text($data['rp_id'] ?? null) ?: self::default_rp_id();
            $inserted = $wpdb->insert(
                $tables['passkey_credentials'],
                [
                    'user_id' => $user_id,
                    'credential_id' => $credential_id,
                    'public_key_pem' => self::nullable_textarea($data['public_key_pem'] ?? null),
                    'public_key_cose' => self::nullable_textarea($data['public_key_cose'] ?? null),
                    'sign_count' => absint($data['sign_count'] ?? 0),
                    'transports_json' => self::json($data['transports'] ?? null),
                    'aaguid' => self::nullable_text($data['aaguid'] ?? null),
                    'rp_id' => $rp_id,
                    'label' => self::nullable_text($data['label'] ?? null),
                    'status' => 'active',
                    'created_at' => self::now(),
                    'updated_at' => self::now(),
                ],
                ['%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
            );

            if (!$inserted) {
                return self::error('credential_insert_failed', 'Could not register passkey credential.');
            }

            return ['success' => true, 'passkey_credential_id' => (int) $wpdb->insert_id, 'rp_id' => $rp_id];
        }

        /**
         * @return array<string,mixed>
         */
        public static function issue_passkey_challenge(int $user_id, string $credential_id = '', string $type = 'authentication'): array
        {
            global $wpdb;

            $tables = APFreepass_Schema::tables();
            $challenge = bin2hex(random_bytes(32));
            $rp_id = self::default_rp_id();
            $inserted = $wpdb->insert(
                $tables['passkey_challenges'],
                [
                    'user_id' => $user_id,
                    'credential_id' => self::nullable_text($credential_id),
                    'challenge_hash' => self::hash_secret($challenge),
                    'challenge_type' => self::allowed($type, ['registration', 'authentication'], 'authentication'),
                    'rp_id' => $rp_id,
                    'origin' => home_url(),
                    'status' => 'issued',
                    'expires_at' => self::expires_in(5 * MINUTE_IN_SECONDS),
                    'created_at' => self::now(),
                    'updated_at' => self::now(),
                ],
                ['%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
            );

            if (!$inserted) {
                return self::error('passkey_challenge_insert_failed', 'Could not issue passkey challenge.');
            }

            return ['success' => true, 'passkey_challenge_id' => (int) $wpdb->insert_id, 'challenge' => $challenge, 'rp_id' => $rp_id];
        }

        /**
         * @param array<string,mixed> $verification
         * @return array<string,mixed>
         */
        public static function record_passkey_verification(int $challenge_id, bool $verified, array $verification): array
        {
            global $wpdb;

            $tables = APFreepass_Schema::tables();
            $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM %i WHERE id = %d", $tables['passkey_challenges'], $challenge_id));
            if (!$row) {
                return self::error('passkey_challenge_not_found', 'Passkey challenge was not found.');
            }

            $status = $verified ? 'verified' : 'failed';
            $wpdb->update(
                $tables['passkey_challenges'],
                [
                    'status' => $status,
                    'verified_at' => $verified ? self::now() : null,
                    'verification_json' => self::json($verification),
                    'updated_at' => self::now(),
                ],
                ['id' => $challenge_id],
                ['%s', '%s', '%s', '%s'],
                ['%d']
            );
            self::audit((int) $row->user_id, 'passkey', $verified ? 'success' : 'failure', $verified ? 'webauthn_verified' : 'webauthn_failed', $verification);

            return ['success' => true, 'passkey_challenge_id' => $challenge_id, 'status' => $status];
        }

        /**
         * @return array<string,mixed>
         */
        public static function create_identity_resolver(string $resolver_key, string $resolver_type, array $config = [], bool $enabled = true): array
        {
            global $wpdb;

            $tables = APFreepass_Schema::tables();
            $resolver_key = sanitize_key($resolver_key);
            $existing_id = (int) $wpdb->get_var($wpdb->prepare("SELECT id FROM %i WHERE resolver_key = %s", $tables['identity_resolvers'], $resolver_key));
            $row = [
                'resolver_key' => $resolver_key,
                'resolver_type' => self::allowed($resolver_type, ['wordpress_user_email', 'wordpress_user_meta', 'crm_optional_contact_phone'], 'wordpress_user_meta'),
                'priority' => absint($config['priority'] ?? 10),
                'config_json' => self::json($config),
                'enabled' => $enabled ? 1 : 0,
                'updated_at' => self::now(),
            ];

            if ($existing_id > 0) {
                $updated = $wpdb->update(
                    $tables['identity_resolvers'],
                    $row,
                    ['id' => $existing_id],
                    ['%s', '%s', '%d', '%s', '%d', '%s'],
                    ['%d']
                );
                if ($updated === false) {
                    return self::error('resolver_update_failed', 'Could not update identity resolver.');
                }

                return ['success' => true, 'identity_resolver_id' => $existing_id];
            }

            $row['created_at'] = self::now();
            $inserted = $wpdb->insert(
                $tables['identity_resolvers'],
                $row,
                ['%s', '%s', '%d', '%s', '%d', '%s', '%s']
            );

            if (!$inserted) {
                return self::error('resolver_insert_failed', 'Could not create identity resolver.');
            }

            return ['success' => true, 'identity_resolver_id' => (int) $wpdb->insert_id];
        }

        /**
         * @return array<string,mixed>
         */
        public static function audit(?int $user_id, string $method, string $result, string $reason = '', array $metadata = []): array
        {
            global $wpdb;

            $tables = APFreepass_Schema::tables();
            $inserted = $wpdb->insert(
                $tables['login_audit'],
                [
                    'user_id' => $user_id,
                    'method' => self::allowed($method, ['magic_link', 'sms_code', 'passkey'], 'magic_link'),
                    'result' => self::allowed($result, ['success', 'failure', 'denied', 'expired', 'rate_limited'], 'failure'),
                    'reason' => self::nullable_text($reason),
                    'metadata_json' => self::json($metadata),
                    'created_at' => self::now(),
                ],
                ['%d', '%s', '%s', '%s', '%s', '%s']
            );

            if (!$inserted) {
                return self::error('audit_insert_failed', 'Could not create audit record.');
            }

            return ['success' => true, 'audit_id' => (int) $wpdb->insert_id];
        }

        private static function hash_secret(string $secret): string
        {
            return hash_hmac('sha256', $secret, wp_salt('auth'));
        }

        private static function default_rp_id(): string
        {
            return function_exists('apfreepass_rp_id')
                ? apfreepass_rp_id()
                : (preg_replace('/^www\./', '', strtolower((string) wp_parse_url(home_url('/'), PHP_URL_HOST))) ?: 'localhost');
        }

        private static function normalize_phone(string $phone): ?string
        {
            $digits = preg_replace('/[^0-9]/', '', $phone);
            if (!$digits) {
                return null;
            }
            if (strlen($digits) === 10) {
                return '+1' . $digits;
            }
            if (strlen($digits) === 11 && $digits[0] === '1') {
                return '+' . $digits;
            }
            return '+' . $digits;
        }

        /**
         * @param array<string> $allowed
         */
        private static function allowed(string $value, array $allowed, string $fallback): string
        {
            $value = sanitize_key($value);
            return in_array($value, $allowed, true) ? $value : $fallback;
        }

        private static function nullable_text($value): ?string
        {
            if ($value === null) {
                return null;
            }
            $value = sanitize_text_field((string) $value);
            return $value === '' ? null : $value;
        }

        private static function nullable_textarea($value): ?string
        {
            if ($value === null) {
                return null;
            }
            $value = sanitize_textarea_field((string) $value);
            return $value === '' ? null : $value;
        }

        private static function nullable_url($value): ?string
        {
            $value = self::nullable_text($value);
            return $value ? esc_url_raw($value) : null;
        }

        private static function json($value): ?string
        {
            if ($value === null || $value === '') {
                return null;
            }
            return wp_json_encode($value);
        }

        private static function now(): string
        {
            return gmdate('Y-m-d H:i:s');
        }

        private static function expires_in(int $seconds): string
        {
            return gmdate('Y-m-d H:i:s', time() + $seconds);
        }

        private static function is_expired(string $value): bool
        {
            $expires = DateTimeImmutable::createFromFormat(
                '!Y-m-d H:i:s',
                $value,
                new DateTimeZone('UTC')
            );
            return !$expires || $expires->getTimestamp() < time();
        }

        /**
         * @return array<string,mixed>
         */
        private static function error(string $code, string $message): array
        {
            return ['success' => false, 'code' => $code, 'message' => $message];
        }
        /**
         * Find user by email or phone for passwordless authentication
         * @return array<string,mixed>
         */
        public static function find_user_for_auth(string $identifier): array
        {
            global $wpdb;

            $identifier = sanitize_text_field($identifier);

            // Try to find user by email
            if (is_email($identifier)) {
                $user = get_user_by('email', $identifier);
                if ($user) {
                    return ['success' => true, 'user_id' => $user->ID, 'email' => $user->user_email];
                }
            }

            // Try to find user by phone (stored in user meta)
            $phone_digits = preg_replace('/[^0-9]/', '', $identifier);
            if (strlen($phone_digits) >= 10) {
                $users = get_users([
                    'meta_key' => 'apfreepass_phone',
                    'meta_value' => $phone_digits,
                    'number' => 2,
                ]);
                // Do not choose an arbitrary account when a number is shared.
                if (count($users) > 1) return self::error('user_not_found', 'No account found with that email or phone number.');
                if (count($users) === 1) {
                    $user = $users[0];
                    return ['success' => true, 'user_id' => $user->ID, 'phone' => $phone_digits];
                }
            }

            // Try to find by username
            $user = get_user_by('login', $identifier);
            if ($user) {
                return ['success' => true, 'user_id' => $user->ID, 'username' => $user->user_login];
            }

            return ['success' => false, 'code' => 'user_not_found', 'message' => 'No account found with that email or phone number.'];
        }

        /**
         * Send magic link via email
         * @return array<string,mixed>
         */
        public static function send_magic_link_email(int $magic_link_id, string $token, string $email, string $redirect_url = ''): array
        {
            $magic_link_url = add_query_arg([
                'apfreepass_magic_token' => $token,
                'redirect' => $redirect_url ?: admin_url(),
            ], home_url('/'));
            $magic_link_url = (string) apply_filters(
                'apfreepass_magic_link_url',
                $magic_link_url,
                $token,
                $redirect_url
            );

            $site_name = (string) apply_filters('apfreepass_site_name', get_bloginfo('name'));
            // translators: %s: site name.
            $subject = sprintf(__('Your magic link for %s', 'artistpro-freepass'), $site_name);

            $message = sprintf(
                /* translators: 1: site name, 2: sign-in URL, 3: site name. */
                __("Hello,\n\nClick the link below to sign in to %1\$s:\n\n%2\$s\n\nThis link expires in 15 minutes.\n\nIf you didn't request this link, you can safely ignore this email.\n\n--\n%3\$s Team", 'artistpro-freepass'),
                $site_name,
                $magic_link_url,
                $site_name
            );

            $headers = ['Content-Type: text/plain; charset=UTF-8'];

            $sent = wp_mail($email, $subject, $message, $headers);

            if ($sent) {
                global $wpdb;
                $tables = APFreepass_Schema::tables();
                $wpdb->update(
                    $tables['magic_links'],
                    ['status' => 'sent', 'updated_at' => self::now()],
                    ['id' => $magic_link_id, 'status' => 'issued'],
                    ['%s', '%s'],
                    ['%d', '%s']
                );
                self::audit(null, 'magic_link', 'success', 'sent', ['email' => $email, 'magic_link_id' => $magic_link_id]);
                return ['success' => true, 'message' => 'Magic link sent to email.'];
            }

            self::audit(null, 'magic_link', 'failure', 'email_failed', ['email' => $email, 'magic_link_id' => $magic_link_id]);
            return ['success' => false, 'code' => 'email_failed', 'message' => 'Failed to send magic link email.'];
        }

        /**
         * Handle magic link verification endpoint
         * @return array<string,mixed>
         */
        public static function handle_magic_link_verification(string $token): array
        {
            global $wpdb;
            $tables = APFreepass_Schema::tables();
            $verified = self::verify_magic_link($token);
            if (empty($verified['success'])) return $verified;
            $user_id = (int) $verified['user_id'];
            if (!get_userdata($user_id)) return self::error('user_not_found', 'The account no longer exists.');
            $row = $wpdb->get_row($wpdb->prepare("SELECT redirect_url FROM %i WHERE id = %d", $tables['magic_links'], (int) $verified['magic_link_id']));
            $redirect = wp_validate_redirect((string) ($row->redirect_url ?? '') ?: admin_url(), admin_url());
            wp_set_current_user($user_id);
            wp_set_auth_cookie($user_id, true);
            self::audit($user_id, 'magic_link', 'success', 'login', ['magic_link_id' => (int) $verified['magic_link_id']]);
            return ['success' => true, 'user_id' => $user_id, 'redirect' => $redirect];
        }

        /**
         * Register a new passkey credential
         * @param array<string,mixed> $data
         * @return array<string,mixed>
         */
        public static function register_passkey(int $user_id, array $data): array
        {
            global $wpdb;
            $tables = APFreepass_Schema::tables();

            $credential_id = self::nullable_text($data['credential_id'] ?? null);
            if (!$credential_id) {
                return self::error('credential_id_required', 'Credential ID is required.');
            }

            $rp_id = self::default_rp_id();
            $inserted = $wpdb->insert(
                $tables['passkey_credentials'],
                [
                    'user_id' => $user_id,
                    'credential_id' => $credential_id,
                    'public_key_pem' => self::nullable_textarea($data['public_key_pem'] ?? null),
                    'public_key_cose' => self::nullable_textarea($data['public_key_cose'] ?? null),
                    'sign_count' => absint($data['sign_count'] ?? 0),
                    'transports_json' => self::json($data['transports'] ?? null),
                    'aaguid' => self::nullable_text($data['aaguid'] ?? null),
                    'rp_id' => $rp_id,
                    'label' => self::nullable_text($data['label'] ?? null),
                    'status' => 'active',
                    'created_at' => self::now(),
                    'updated_at' => self::now(),
                ],
                ['%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
            );

            if (!$inserted) {
                return self::error('credential_insert_failed', 'Could not register passkey credential.');
            }

            return ['success' => true, 'passkey_credential_id' => (int) $wpdb->insert_id, 'rp_id' => $rp_id];
        }

        /**
         * Get passkey credentials for a user
         * @return array<string,mixed>
         */
        public static function get_passkey_credentials(int $user_id): array
        {
            global $wpdb;
            $tables = APFreepass_Schema::tables();
            $rows = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM %i WHERE user_id = %d AND status = 'active'",
                $tables['passkey_credentials'], $user_id
            ));

            return ['success' => true, 'credentials' => $rows];
        }

        /**
         * Get passkey credential by credential ID
         * @return array<string,mixed>
         */
        public static function get_passkey_by_credential_id(string $credential_id): array
        {
            global $wpdb;
            $tables = APFreepass_Schema::tables();
            $row = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM %i WHERE credential_id = %s AND status = 'active'",
                $tables['passkey_credentials'], $credential_id
            ));

            if (!$row) {
                return self::error('credential_not_found', 'Passkey credential not found.');
            }

            return ['success' => true, 'credential' => $row];
        }

        /**
         * Update passkey last used timestamp
         * @return array<string,mixed>
         */
        public static function update_passkey_last_used(int $credential_id): array
        {
            global $wpdb;
            $tables = APFreepass_Schema::tables();
            $wpdb->update(
                $tables['passkey_credentials'],
                ['last_used_at' => self::now(), 'updated_at' => self::now()],
                ['id' => $credential_id],
                ['%s', '%s'],
                ['%d']
            );
            return ['success' => true];
        }
    }
}
