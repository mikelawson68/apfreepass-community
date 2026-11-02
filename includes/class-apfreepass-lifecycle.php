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
    }
}
