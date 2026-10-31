<?php
/**
 * apFreepass public domain contract.
 *
 * @package apFreepass
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('APFreepass_Contract')) {
    final class APFreepass_Contract
    {
        /**
         * @return array<string,mixed>
         */
        public static function component(): array
        {
            return [
                'key' => 'apfreepass',
                'name' => 'apFreepass',
                'layer' => 'standalone_plugin',
                'status' => 'first_working_spine',
                'responsibility' => 'Passwordless WordPress authentication records for magic links, SMS challenges, passkey credentials, passkey challenges, identity resolvers, and login audit events.',
                'theme_boundary' => self::theme_boundary_contract(),
                'depends_on' => [],
                'optional_integrations' => ['apAuth', 'apSecurity', 'apSMS', 'apCRM optional resolver', 'apEmail', 'WebAuthn verifier library/service'],
            ];
        }

        /**
         * @return array<string,mixed>
         */
        public static function domain(): array
        {
            return [
                'owns' => [
                    'magic_link_challenges',
                    'sms_code_challenges',
                    'passkey_credentials',
                    'passkey_challenges',
                    'passwordless_identity_resolver_rules',
                    'passwordless_settings_contract',
                    'login_attempt_audit_records',
                    'passwordless_method_policy',
                ],
                'does_not_own' => [
                    'sms_provider_credentials',
                    'sms_gateway_execution',
                    'email_delivery_engine',
                    'crm_contact_truth',
                    'portal_authentication_ui',
                    'security_lockout_policy',
                    'webauthn_crypto_library',
                ],
                'hard_rules' => [
                    'apFreepass can be used on plain WordPress without PubMotor CRM.',
                    'apFreepass core must not require apSMS, apCRM, apEmail, apSecurity, or apAuth to activate.',
                    'Magic links may use WordPress email by default, but email delivery can be delegated to apEmail or another mail connector.',
                    'SMS challenge delivery is connector-owned; apFreepass creates the challenge and apSMS or another SMS connector sends it.',
                    'If no SMS connector is configured, SMS login is disabled while magic link and passkey modes remain available.',
                    'Twilio is one provider option only; SMS provider selection must be configurable and connector-owned.',
                    'CRM/PubMotor identity lookup is optional and must be implemented as a resolver, not a core dependency.',
                    'Passkey RP ID must be derived from the current site or configured setting, never hardcoded to artistpro.media.',
                    'Passkey login must require full WebAuthn challenge and signature verification before WordPress auth cookies are set.',
                    'Credential public keys and counters may be stored; raw private keys, passwords, and unverified credential blobs must never be trusted.',
                    'The old ArtistPro satellite actions and route names must be treated as legacy compatibility, not product contract names.',
                    'Suite UI alignment can happen later, but settings and method policy must be explicit from this first spine.',
                ],
                'settings_policy' => [
                    'default_methods' => ['magic_link'],
                    'optional_methods' => ['sms_code', 'passkey'],
                    'standalone_without_sms' => 'valid_supported_mode',
                    'settings_resolution_order' => ['site_override', 'network_override', 'shared_pubmotor_auth_registry', 'plugin_defaults'],
                    'sms_resolution_order' => ['apfreepass_sms_override', 'shared_apsms_provider_registry', 'disabled'],
                    'crm_resolver_default' => 'disabled',
                    'rp_id_rule' => 'Use configured rp_id when set, otherwise derive from home_url host.',
                ],
                'sms_provider_policy' => [
                    'default_mode' => 'disabled_until_provider_configured',
                    'dependency_mode' => 'optional_integration_not_required_dependency',
                    'provider_options' => ['twilio', 'telnyx', 'messagebird', 'plivo', 'vonage', 'sms77', 'gatewayapi', 'custom_webhook', 'mock'],
                    'future_module' => 'apSMS',
                    'data_rule' => 'SMS provider credentials and gateway execution belong to apSMS or another connector, never apFreepass core tables.',
                ],
                'passkey_policy' => [
                    'registration_statuses' => ['pending', 'active', 'revoked'],
                    'challenge_statuses' => ['planned', 'issued', 'verified', 'failed', 'expired', 'cancelled'],
                    'verification_rule' => 'A credential ID match is not enough. WebAuthn authenticator data, client data JSON, origin, RP ID hash, signature, challenge, and sign counter must be verified.',
                ],
                'challenge_statuses' => ['planned', 'issued', 'verified', 'failed', 'expired', 'cancelled'],
                'login_methods' => ['magic_link', 'sms_code', 'passkey'],
                'login_results' => ['success', 'failure', 'denied', 'expired', 'rate_limited'],
            ];
        }
        /**
         * Suite-wide theme isolation contract.
         *
         * @return array<string,mixed>
         */
        public static function theme_boundary_contract(): array
        {
            return [
                'themes_are_presentation_only' => true,
                'plugin_owned_surfaces' => ['data', 'schema', 'routes', 'permissions', 'workflow_state', 'integrations', 'business_rules'],
                'theme_owned_surfaces' => ['visual_rendering', 'CSS', 'template_slot_markup'],
                'hard_rules' => [
                    'No module business logic may live in a WordPress theme.',
                    'Plugin-owned routes must render through plugin-owned templates or skins by default.',
                    'Themes may style or override approved presentation slots only; they must not decide billing, CRM, sales, ads, subscriptions, print, portal, security, AI, or connector behavior.',
                    'If a theme is disabled or changed, the plugin must continue to function with its default skin.',
                    'Theme failures may make a screen ugly; they must not make business state wrong.',
                ],
            ];
        }
    }
}
