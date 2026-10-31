<?php
/**
 * apFreepass WP-CLI commands.
 *
 * @package apFreepass
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

if (defined('WP_CLI') && WP_CLI && !class_exists('APFreepass_CLI')) {
    final class APFreepass_CLI
    {
        public function install(): void
        {
            APFreepass_Schema::install();
            WP_CLI::success('apFreepass schema installed for current site.');
        }

        public function contract(): void
        {
            WP_CLI::line(wp_json_encode(apfreepass_contract(), JSON_PRETTY_PRINT));
        }

        public function smoke_lifecycle(): void
        {
            APFreepass_Schema::install();

            $policy = APFreepass_Lifecycle::create_method_policy(
                [
                    'scope_type' => 'site',
                    'scope_id' => 0,
                    'magic_link_enabled' => true,
                    'sms_enabled' => true,
                    'passkey_enabled' => true,
                    'allowed_roles' => ['administrator', 'editor'],
                    'sms_provider_ref' => 'apsms:mock',
                    'crm_resolver_enabled' => false,
                ]
            );
            $this->assert_success($policy, 'method policy');

            $user_id = get_current_user_id() ?: 1;
            $magic = APFreepass_Lifecycle::issue_magic_link($user_id, 'freepass-smoke@example.test', admin_url());
            $this->assert_success($magic, 'magic link issue');

            $magic_verify = APFreepass_Lifecycle::verify_magic_link((string) $magic['token']);
            $this->assert_success($magic_verify, 'magic link verify');

            $sms = APFreepass_Lifecycle::issue_sms_challenge($user_id, '+15551234567', 'apsms:mock');
            $this->assert_success($sms, 'sms challenge issue');

            $sms_verify = APFreepass_Lifecycle::verify_sms_challenge((int) $sms['sms_challenge_id'], (string) $sms['code']);
            $this->assert_success($sms_verify, 'sms challenge verify');

            $credential = APFreepass_Lifecycle::register_passkey_credential(
                $user_id,
                [
                    'credential_id' => 'smoke-credential-' . gmdate('YmdHis'),
                    'public_key_pem' => '-----BEGIN PUBLIC KEY----- smoke -----END PUBLIC KEY-----',
                    'public_key_cose' => '{"kty":"EC2","note":"smoke placeholder"}',
                    'sign_count' => 1,
                    'transports' => ['internal', 'hybrid'],
                    'label' => 'Smoke Passkey',
                ]
            );
            $this->assert_success($credential, 'passkey credential');

            $challenge = APFreepass_Lifecycle::issue_passkey_challenge($user_id, 'smoke-credential-' . gmdate('YmdHis'), 'authentication');
            $this->assert_success($challenge, 'passkey challenge');

            $passkey_verify = APFreepass_Lifecycle::record_passkey_verification(
                (int) $challenge['passkey_challenge_id'],
                true,
                [
                    'verified_by' => 'external_webauthn_verifier_required',
                    'rp_id' => $challenge['rp_id'],
                    'credential_id_match_only_is_not_sufficient' => true,
                    'signature_verified' => true,
                    'origin_verified' => true,
                    'sign_counter_checked' => true,
                ]
            );
            $this->assert_success($passkey_verify, 'passkey verification record');

            $resolver_wp = APFreepass_Lifecycle::create_identity_resolver('wp_phone_meta', 'wordpress_user_meta', ['meta_key' => 'phone', 'priority' => 10], true);
            $this->assert_success($resolver_wp, 'WP resolver');

            $resolver_crm = APFreepass_Lifecycle::create_identity_resolver('crm_contact_phone_optional', 'crm_optional_contact_phone', ['module' => 'apCRM', 'priority' => 30], false);
            $this->assert_success($resolver_crm, 'optional CRM resolver');

            WP_CLI::line(
                wp_json_encode(
                    [
                        'success' => true,
                        'method_policy_id' => $policy['method_policy_id'],
                        'rp_id' => $policy['rp_id'],
                        'magic_link_id' => $magic['magic_link_id'],
                        'magic_verified_user_id' => $magic_verify['user_id'],
                        'sms_challenge_id' => $sms['sms_challenge_id'],
                        'sms_verified_user_id' => $sms_verify['user_id'],
                        'passkey_credential_id' => $credential['passkey_credential_id'],
                        'passkey_challenge_id' => $challenge['passkey_challenge_id'],
                        'passkey_verification_status' => $passkey_verify['status'],
                        'wp_resolver_id' => $resolver_wp['identity_resolver_id'],
                        'crm_resolver_id' => $resolver_crm['identity_resolver_id'],
                    ],
                    JSON_PRETTY_PRINT
                )
            );
        }

        public function smoke_standalone_no_sms(): void
        {
            APFreepass_Schema::install();

            $policy = APFreepass_Lifecycle::create_method_policy(
                [
                    'scope_type' => 'site',
                    'scope_id' => 0,
                    'magic_link_enabled' => true,
                    'sms_enabled' => false,
                    'passkey_enabled' => true,
                    'allowed_roles' => ['administrator'],
                    'sms_provider_ref' => '',
                    'crm_resolver_enabled' => false,
                ]
            );
            $this->assert_success($policy, 'standalone policy');

            $user_id = get_current_user_id() ?: 1;
            $magic = APFreepass_Lifecycle::issue_magic_link($user_id, 'freepass-standalone@example.test', admin_url());
            $this->assert_success($magic, 'standalone magic link issue');

            $magic_verify = APFreepass_Lifecycle::verify_magic_link((string) $magic['token']);
            $this->assert_success($magic_verify, 'standalone magic link verify');

            $credential_id = 'standalone-credential-' . gmdate('YmdHis');
            $credential = APFreepass_Lifecycle::register_passkey_credential(
                $user_id,
                [
                    'credential_id' => $credential_id,
                    'public_key_cose' => '{"kty":"EC2","note":"standalone smoke placeholder"}',
                    'sign_count' => 1,
                    'transports' => ['internal'],
                    'label' => 'Standalone Smoke Passkey',
                ]
            );
            $this->assert_success($credential, 'standalone passkey credential');

            $challenge = APFreepass_Lifecycle::issue_passkey_challenge($user_id, $credential_id, 'authentication');
            $this->assert_success($challenge, 'standalone passkey challenge');

            $passkey_verify = APFreepass_Lifecycle::record_passkey_verification(
                (int) $challenge['passkey_challenge_id'],
                true,
                [
                    'verified_by' => 'external_webauthn_verifier_required',
                    'standalone_without_sms' => true,
                    'sms_dependency_required' => false,
                    'signature_verified' => true,
                    'origin_verified' => true,
                    'sign_counter_checked' => true,
                ]
            );
            $this->assert_success($passkey_verify, 'standalone passkey verification record');

            WP_CLI::line(
                wp_json_encode(
                    [
                        'success' => true,
                        'standalone_without_sms' => true,
                        'method_policy_id' => $policy['method_policy_id'],
                        'sms_enabled' => false,
                        'sms_provider_ref' => null,
                        'rp_id' => $policy['rp_id'],
                        'magic_link_id' => $magic['magic_link_id'],
                        'magic_verified_user_id' => $magic_verify['user_id'],
                        'passkey_credential_id' => $credential['passkey_credential_id'],
                        'passkey_challenge_id' => $challenge['passkey_challenge_id'],
                        'passkey_verification_status' => $passkey_verify['status'],
                    ],
                    JSON_PRETTY_PRINT
                )
            );
        }

        /**
         * @param array<string,mixed> $result
         */
        private function assert_success(array $result, string $label): void
        {
            if (empty($result['success'])) {
                WP_CLI::error($label . ' failed: ' . ($result['message'] ?? 'unknown error'));
            }
        }
    }

    WP_CLI::add_command('apfreepass', 'APFreepass_CLI');
}
