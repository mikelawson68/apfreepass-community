<?php
declare(strict_types=1);

defined('ABSPATH') || exit;

final class APFreepass_WebAuthn
{
    public static function boot(): void
    {
        $autoload = dirname(__DIR__) . '/vendor/autoload.php';
        if (!is_readable($autoload)) { return; }
        require_once $autoload;
        \lbuchs\WebAuthn\Binary\ByteBuffer::$useBase64UrlEncoding = true;
        add_action('wp_ajax_apfreepass_passkey_get_registration_challenge', [self::class, 'registration_options']);
        add_action('wp_ajax_apfreepass_passkey_register_credential', [self::class, 'register']);
        add_action('wp_ajax_apfreepass_passkey_revoke', [self::class, 'revoke']);
        add_action('wp_ajax_nopriv_apfreepass_passkey_get_challenge', [self::class, 'authentication_options']);
        add_action('wp_ajax_apfreepass_passkey_get_challenge', [self::class, 'authentication_options']);
        add_action('wp_ajax_nopriv_apfreepass_passkey_verify_assertion', [self::class, 'authenticate']);
        add_action('wp_ajax_apfreepass_passkey_verify_assertion', [self::class, 'authenticate']);
    }

    private static function webauthn(): \lbuchs\WebAuthn\WebAuthn
    {
        return new \lbuchs\WebAuthn\WebAuthn(get_bloginfo('name'), apfreepass_rp_id(), ['none']);
    }

    private static function decode(string $value): string
    {
        return \lbuchs\WebAuthn\Binary\ByteBuffer::fromBase64Url($value)->getBinaryString();
    }

    /** Read bounded base64url fields without changing their encoded bytes. */
    private static function input_b64(string $name, bool $optional = false): string
    {
        // Every caller checks the apfreepass_auth nonce before reading request fields.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified at each public AJAX handler.
        $raw = isset($_POST[$name]) && is_string($_POST[$name]) ? sanitize_text_field(wp_unslash($_POST[$name])) : '';
        if ($optional && $raw === '') return '';
        if ($raw === '' || strlen($raw) > 262144 || !preg_match('/^[A-Za-z0-9_-]+$/', $raw)) {
            throw new RuntimeException('Invalid passkey response.');
        }
        return $raw;
    }

    private static function encode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    /** Require the exact WordPress site origin, not merely an RP-ID suffix. */
    private static function assert_site_origin(string $client_data): void
    {
        $data = json_decode($client_data, true);
        $origin = is_array($data) && is_string($data['origin'] ?? null) ? $data['origin'] : '';
        $actual = wp_parse_url($origin);
        $site = wp_parse_url(home_url('/'));
        if (!is_array($data) || !empty($data['crossOrigin']) || !is_array($actual) || !is_array($site) || empty($actual['scheme']) || empty($actual['host']) || empty($site['scheme']) || empty($site['host']) || isset($actual['user']) || isset($actual['pass']) || isset($actual['query']) || isset($actual['fragment']) || !empty($actual['path'])) {
            throw new RuntimeException('Invalid passkey origin.');
        }
        $scheme = strtolower($actual['scheme']); $site_scheme = strtolower($site['scheme']);
        $host = strtolower(rtrim($actual['host'], '.')); $site_host = strtolower(rtrim($site['host'], '.'));
        $port = $actual['port'] ?? ($scheme === 'https' ? 443 : 80);
        $site_port = $site['port'] ?? ($site_scheme === 'https' ? 443 : 80);
        $secure_local = $scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '::1'], true);
        if (($scheme !== 'https' && !$secure_local) || $scheme !== $site_scheme || $host !== $site_host || $port !== $site_port) {
            throw new RuntimeException('Invalid passkey origin.');
        }
    }

    private static function assert_user_handle(string $handle, int $user_id): void
    {
        if ($handle === '') return; // Authenticators may omit the optional handle.
        if (!preg_match('/^[A-Za-z0-9_-]+$/', $handle) || !hash_equals((string) $user_id, self::decode($handle))) {
            throw new RuntimeException('Passkey user handle mismatch.');
        }
    }

    /** Serialize verification and counter updates for the same credential. */
    private static function with_credential_lock(string $credential_id, callable $work)
    {
        global $wpdb;
        $lock = 'apfp_cred_' . substr(hash('sha256', $wpdb->prefix . ':' . $credential_id), 0, 40);
        if ((string) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', $lock)) !== '1') {
            throw new RuntimeException('Passkey verification already in progress.');
        }
        try { return $work(); }
        finally { $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock)); }
    }

    private static function challenge_key(string $id): string { return 'apfreepass_webauthn_' . $id; }

    /** Atomically consume a challenge before cryptographic verification. */
    private static function claim_challenge(string $id, string $type, int $user_id = 0): ?array
    {
        global $wpdb;
        if (!preg_match('/^[a-f0-9-]{36}$/i', $id) || !in_array($type, ['registration', 'authentication'], true)) return null;
        $lock = 'apfp_pk_' . substr(hash('sha256', $wpdb->prefix . ':' . $id), 0, 40);
        if ((string) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', $lock)) !== '1') return null;
        try {
            $key = self::challenge_key($id);
            $state = get_transient($key);
            if (!is_array($state) || ($state['type'] ?? '') !== $type || empty($state['challenge']) || empty($state['user_id']) || ($user_id && (int) $state['user_id'] !== $user_id)) return null;
            // Fail closed if the challenge cannot be deleted. A failed attempt must
            // request a fresh challenge; no response can be verified twice.
            if (!delete_transient($key)) return null;
            return $state;
        } finally {
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
        }
    }

    public static function registration_options(): void
    {
        check_ajax_referer('apfreepass_auth', 'nonce');
        apfreepass_require_method('passkey');
        if (!is_user_logged_in()) { wp_send_json_error(['message'=>'Sign in before adding a passkey.'], 401); }
        $user = wp_get_current_user();
        global $wpdb;
        $tables = APFreepass_Schema::tables();
        $existing = $wpdb->get_col($wpdb->prepare("SELECT credential_id FROM %i WHERE user_id=%d AND status='active'", $tables['passkey_credentials'], $user->ID));
        $exclude = array_map(static fn(string $id): string => self::decode($id), $existing);
        $args = self::webauthn()->getCreateArgs((string)$user->ID, $user->user_email, $user->display_name, 60, 'preferred', 'required', null, $exclude);
        $challenge_id = wp_generate_uuid4();
        $challenge = $args->publicKey->challenge->getBinaryString();
        if (!set_transient(self::challenge_key($challenge_id), ['type'=>'registration','user_id'=>$user->ID,'challenge'=>self::encode($challenge)], 5 * MINUTE_IN_SECONDS)) { wp_send_json_error(['message'=>'Passkey setup is temporarily unavailable.'], 503); }
        wp_send_json_success(['challenge'=>self::encode($challenge),'challenge_id'=>$challenge_id,'user_id'=>self::encode((string)$user->ID)]);
    }

    public static function register(): void
    {
        check_ajax_referer('apfreepass_auth', 'nonce');
        apfreepass_require_method('passkey');
        if (!is_user_logged_in()) { wp_send_json_error(['message'=>'Sign in before adding a passkey.'], 401); }
        $challenge_id = sanitize_text_field((string) wp_unslash($_POST['challenge_id'] ?? ''));
        $state = self::claim_challenge($challenge_id, 'registration', get_current_user_id());
        if (!$state) {
            wp_send_json_error(['message'=>'Passkey setup expired. Start again.'], 400);
        }
        try {
            $client_data = self::decode(self::input_b64('client_data_json'));
            self::assert_site_origin($client_data);
            $data = self::webauthn()->processCreate(
                $client_data,
                self::decode(self::input_b64('attestation_object')),
                self::decode((string)$state['challenge']),
                true,
                true,
                false
            );
            $credential_id = self::encode((string)$data->credentialId);
            $transport_json = isset($_POST['transports']) && is_string($_POST['transports']) ? sanitize_text_field(wp_unslash($_POST['transports'])) : '[]';
            $transports = json_decode($transport_json, true);
            $transports = is_array($transports) ? array_values(array_filter($transports, static fn($transport): bool => is_string($transport) && in_array($transport, ['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card'], true))) : [];
            $result = APFreepass_Lifecycle::register_passkey_credential(get_current_user_id(), [
                'credential_id'=>$credential_id,
                'public_key_pem'=>(string)$data->credentialPublicKey,
                'sign_count'=>(int)($data->signatureCounter ?? 0),
                'transports'=>$transports,
                'aaguid'=>isset($data->AAGUID) ? bin2hex((string)$data->AAGUID) : '',
                'label'=>sanitize_text_field((string) wp_unslash($_POST['device_name'] ?? 'Passkey')) ?: 'Passkey',
            ]);
            if (empty($result['success'])) { throw new RuntimeException((string)($result['message'] ?? 'Could not save passkey.')); }
            wp_send_json_success(['message'=>'Passkey added.','redirect'=>wp_validate_redirect((string) apply_filters('apfreepass_passkey_registration_redirect', admin_url('profile.php')), admin_url('profile.php'))]);
        } catch (Throwable $e) {
            APFreepass_Lifecycle::audit(get_current_user_id(), 'passkey', 'failure', 'registration_failed');
            wp_send_json_error(['message'=>'The passkey could not be verified. Please try again.'], 400);
        }
    }

    /** List only the signed-in account's active credentials, without key material. */
    public static function list_for_user(int $user_id): array
    {
        if ($user_id < 1) return [];
        global $wpdb; $tables = APFreepass_Schema::tables();
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT id, label, created_at, last_used_at FROM %i WHERE user_id = %d AND status = 'active' ORDER BY id DESC",
            $tables['passkey_credentials'], $user_id
        ));
        return is_array($rows) ? $rows : [];
    }

    /** Revoke only an owned credential, keeping a route back into the account. */
    public static function revoke_for_user(int $credential_row_id, int $user_id): bool
    {
        if ($credential_row_id < 1 || $user_id < 1) return false;
        global $wpdb; $tables = APFreepass_Schema::tables();
        $lock = 'apfp_user_' . substr(hash('sha256', $wpdb->prefix . ':' . $user_id), 0, 40);
        if ((string) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', $lock)) !== '1') return false;
        try {
            $row = $wpdb->get_row($wpdb->prepare(
                "SELECT id, credential_id FROM %i WHERE id = %d AND user_id = %d AND status = 'active'",
                $tables['passkey_credentials'], $credential_row_id, $user_id
            ));
            if (!$row) return false;
            $count = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM %i WHERE user_id = %d AND status = 'active'",
                $tables['passkey_credentials'], $user_id
            ));
            if ($count === null) return false;
            $phone = preg_replace('/[^0-9]/', '', (string) get_user_meta($user_id, 'apfreepass_phone', true));
            $sms_recovery = apfreepass_method_enabled('sms_code') && function_exists('apsms_request_message') && strlen($phone) >= 10;
            $account = get_userdata($user_id);
            $magic_recovery = apfreepass_method_enabled('magic_link') && $account && is_email($account->user_email);
            $other_method = $magic_recovery || $sms_recovery;
            if ((int) $count <= 1 && !$other_method) return false;
            return self::with_credential_lock((string) $row->credential_id, static function () use ($wpdb, $tables, $credential_row_id, $user_id): bool {
                $updated = $wpdb->update($tables['passkey_credentials'], ['status' => 'revoked', 'updated_at' => current_time('mysql')], ['id' => $credential_row_id, 'user_id' => $user_id, 'status' => 'active']);
                if ($updated !== 1) return false;
                APFreepass_Lifecycle::audit($user_id, 'passkey', 'success', 'revoked');
                return true;
            });
        } catch (Throwable $e) { return false; }
        finally { $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock)); }
    }

    public static function revoke(): void
    {
        check_ajax_referer('apfreepass_auth', 'nonce');
        apfreepass_require_method('passkey');
        if (!is_user_logged_in()) { wp_send_json_error(['message' => 'Sign in before removing a passkey.'], 401); }
        $id = isset($_POST['credential_row_id']) && is_scalar($_POST['credential_row_id']) ? absint($_POST['credential_row_id']) : 0;
        if (!self::revoke_for_user($id, get_current_user_id())) {
            wp_send_json_error(['message' => 'The passkey could not be removed. Keep another sign-in method available.'], 400);
        }
        wp_send_json_success(['message' => 'Passkey removed.']);
    }

    public static function authentication_options(): void
    {
        check_ajax_referer('apfreepass_auth', 'nonce');
        apfreepass_require_method('passkey');
        $login = sanitize_text_field((string) wp_unslash($_POST['username'] ?? ''));
        $user = $login !== '' ? (is_email($login) ? get_user_by('email', $login) : get_user_by('login', $login)) : false;
        if (!$user) { wp_send_json_error(['message'=>'Enter the username or email address for your account.'], 400); }
        global $wpdb;
        $tables = APFreepass_Schema::tables();
        $rows = $wpdb->get_results($wpdb->prepare("SELECT credential_id,transports_json FROM %i WHERE user_id=%d AND status='active'", $tables['passkey_credentials'], $user->ID));
        if (!$rows) { wp_send_json_error(['message'=>'No passkey is registered for this account.'], 404); }
        $challenge = random_bytes(32);
        $challenge_id = wp_generate_uuid4();
        if (!set_transient(self::challenge_key($challenge_id), ['type'=>'authentication','user_id'=>$user->ID,'challenge'=>self::encode($challenge)], 5 * MINUTE_IN_SECONDS)) { wp_send_json_error(['message'=>'Passkey sign-in is temporarily unavailable.'], 503); }
        wp_send_json_success(['challenge'=>self::encode($challenge),'challenge_id'=>$challenge_id,'credentials'=>array_map(static fn($r): array => ['credential_id'=>$r->credential_id,'transports'=>$r->transports_json], $rows)]);
    }

    public static function authenticate(): void
    {
        check_ajax_referer('apfreepass_auth', 'nonce');
        apfreepass_require_method('passkey');
        $challenge_id = sanitize_text_field((string) wp_unslash($_POST['challenge_id'] ?? ''));
        $state = self::claim_challenge($challenge_id, 'authentication');
        $credential_id = sanitize_text_field((string) wp_unslash($_POST['credential_id'] ?? ''));
        $cred = APFreepass_Lifecycle::get_passkey_by_credential_id($credential_id);
        if (!$state || empty($cred['success']) || (int)$cred['credential']->user_id !== (int)$state['user_id']) {
            wp_send_json_error(['message'=>'Passkey sign-in expired. Start again.'], 400);
        }
        try {
            $client_data = self::decode(self::input_b64('client_data_json'));
            self::assert_site_origin($client_data);
            self::assert_user_handle(self::input_b64('user_handle', true), (int) $state['user_id']);
            self::with_credential_lock($credential_id, static function () use ($credential_id, $state, $client_data): void {
                global $wpdb;
                // Reload while holding the lock so concurrent assertions see the latest counter.
                $current = APFreepass_Lifecycle::get_passkey_by_credential_id($credential_id);
                if (empty($current['success']) || (int) $current['credential']->user_id !== (int) $state['user_id']) {
                    throw new RuntimeException('Passkey credential no longer available.');
                }
                $credential = $current['credential'];
                $wa = self::webauthn();
                $wa->processGet(
                    $client_data,
                    self::decode(self::input_b64('authenticator_data')),
                    self::decode(self::input_b64('signature')),
                    (string) $credential->public_key_pem,
                    self::decode((string) $state['challenge']),
                    (int) $credential->sign_count,
                    true,
                    true
                );
                $tables = APFreepass_Schema::tables();
                $new_count = (int) ($wa->getSignatureCounter() ?? $credential->sign_count);
                $updated = $wpdb->update($tables['passkey_credentials'], [
                    'sign_count' => $new_count,
                    'last_used_at' => current_time('mysql'),
                    'updated_at' => current_time('mysql'),
                ], ['id' => (int) $credential->id, 'status' => 'active']);
                if ($updated === false) throw new RuntimeException('Passkey counter could not be saved.');
                if ($updated === 0) {
                    // MySQL may report no changed rows for counterless authenticators.
                    // Accept that only if the credential still exists and is active.
                    $still_current = APFreepass_Lifecycle::get_passkey_by_credential_id($credential_id);
                    if (empty($still_current['success']) || (int) $still_current['credential']->sign_count !== $new_count) {
                        throw new RuntimeException('Passkey credential changed during verification.');
                    }
                }
            });
            wp_set_current_user((int)$state['user_id']);
            wp_set_auth_cookie((int)$state['user_id'], true);
            APFreepass_Lifecycle::audit((int)$state['user_id'], 'passkey', 'success', 'webauthn_verified');
            wp_send_json_success(['message'=>'Authenticated.','redirect'=>wp_validate_redirect(esc_url_raw(wp_unslash((string)($_POST['redirect'] ?? ''))), home_url('/'))]);
        } catch (Throwable $e) {
            APFreepass_Lifecycle::audit((int)$state['user_id'], 'passkey', 'failure', 'webauthn_failed');
            wp_send_json_error(['message'=>'The passkey could not be verified.'], 401);
        }
    }
}

APFreepass_WebAuthn::boot();
