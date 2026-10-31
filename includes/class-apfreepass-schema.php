<?php
/**
 * apFreepass schema installer.
 *
 * @package apFreepass
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('APFreepass_Schema')) {
    final class APFreepass_Schema
    {
        public static function install(): void
        {
            global $wpdb;

            require_once ABSPATH . 'wp-admin/includes/upgrade.php';

            $charset_collate = $wpdb->get_charset_collate();
            $tables = self::tables();

            dbDelta("CREATE TABLE {$tables['method_policy']} (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                scope_type varchar(40) NOT NULL DEFAULT 'site',
                scope_id bigint(20) unsigned NOT NULL DEFAULT 0,
                magic_link_enabled tinyint(1) NOT NULL DEFAULT 1,
                sms_enabled tinyint(1) NOT NULL DEFAULT 0,
                passkey_enabled tinyint(1) NOT NULL DEFAULT 0,
                allowed_roles_json longtext NULL,
                rp_id varchar(255) DEFAULT NULL,
                sms_provider_ref varchar(160) DEFAULT NULL,
                crm_resolver_enabled tinyint(1) NOT NULL DEFAULT 0,
                status varchar(40) NOT NULL DEFAULT 'active',
                created_at datetime NOT NULL,
                updated_at datetime NOT NULL,
                PRIMARY KEY  (id),
                KEY scope_ref (scope_type, scope_id),
                KEY status (status)
            ) {$charset_collate};");

            dbDelta("CREATE TABLE {$tables['magic_links']} (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                user_id bigint(20) unsigned NOT NULL,
                email varchar(255) NOT NULL,
                token_hash varchar(128) NOT NULL,
                redirect_url text NULL,
                status varchar(40) NOT NULL DEFAULT 'planned',
                requested_ip_hash varchar(128) DEFAULT NULL,
                user_agent_hash varchar(128) DEFAULT NULL,
                expires_at datetime NOT NULL,
                used_at datetime DEFAULT NULL,
                created_at datetime NOT NULL,
                updated_at datetime NOT NULL,
                PRIMARY KEY  (id),
                UNIQUE KEY token_hash (token_hash),
                KEY user_id (user_id),
                KEY email (email),
                KEY status (status),
                KEY expires_at (expires_at)
            ) {$charset_collate};");

            dbDelta("CREATE TABLE {$tables['sms_challenges']} (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                user_id bigint(20) unsigned NOT NULL,
                phone_e164 varchar(40) NOT NULL,
                code_hash varchar(128) NOT NULL,
                provider_ref varchar(160) DEFAULT NULL,
                delivery_request_ref varchar(160) DEFAULT NULL,
                status varchar(40) NOT NULL DEFAULT 'planned',
                attempts int(11) NOT NULL DEFAULT 0,
                expires_at datetime NOT NULL,
                verified_at datetime DEFAULT NULL,
                created_at datetime NOT NULL,
                updated_at datetime NOT NULL,
                PRIMARY KEY  (id),
                KEY user_id (user_id),
                KEY phone_e164 (phone_e164),
                KEY status (status),
                KEY expires_at (expires_at)
            ) {$charset_collate};");

            dbDelta("CREATE TABLE {$tables['passkey_credentials']} (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                user_id bigint(20) unsigned NOT NULL,
                credential_id varchar(512) NOT NULL,
                public_key_pem longtext NULL,
                public_key_cose longtext NULL,
                sign_count bigint(20) unsigned NOT NULL DEFAULT 0,
                transports_json longtext NULL,
                aaguid varchar(80) DEFAULT NULL,
                rp_id varchar(255) NOT NULL,
                label varchar(255) DEFAULT NULL,
                status varchar(40) NOT NULL DEFAULT 'active',
                last_used_at datetime DEFAULT NULL,
                created_at datetime NOT NULL,
                updated_at datetime NOT NULL,
                PRIMARY KEY  (id),
                UNIQUE KEY credential_id (credential_id),
                KEY user_id (user_id),
                KEY rp_id (rp_id),
                KEY status (status)
            ) {$charset_collate};");

            dbDelta("CREATE TABLE {$tables['passkey_challenges']} (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                user_id bigint(20) unsigned NOT NULL,
                credential_id varchar(512) DEFAULT NULL,
                challenge_hash varchar(128) NOT NULL,
                challenge_type varchar(40) NOT NULL DEFAULT 'authentication',
                rp_id varchar(255) NOT NULL,
                origin varchar(255) DEFAULT NULL,
                status varchar(40) NOT NULL DEFAULT 'issued',
                expires_at datetime NOT NULL,
                verified_at datetime DEFAULT NULL,
                verification_json longtext NULL,
                created_at datetime NOT NULL,
                updated_at datetime NOT NULL,
                PRIMARY KEY  (id),
                UNIQUE KEY challenge_hash (challenge_hash),
                KEY user_id (user_id),
                KEY credential_id (credential_id),
                KEY status (status),
                KEY expires_at (expires_at)
            ) {$charset_collate};");

            dbDelta("CREATE TABLE {$tables['identity_resolvers']} (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                resolver_key varchar(120) NOT NULL,
                resolver_type varchar(80) NOT NULL DEFAULT 'wordpress_user_meta',
                priority int(11) NOT NULL DEFAULT 10,
                config_json longtext NULL,
                enabled tinyint(1) NOT NULL DEFAULT 1,
                created_at datetime NOT NULL,
                updated_at datetime NOT NULL,
                PRIMARY KEY  (id),
                UNIQUE KEY resolver_key (resolver_key),
                KEY resolver_type (resolver_type),
                KEY enabled (enabled)
            ) {$charset_collate};");

            dbDelta("CREATE TABLE {$tables['login_audit']} (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                user_id bigint(20) unsigned DEFAULT NULL,
                method varchar(40) NOT NULL,
                result varchar(40) NOT NULL,
                reason varchar(160) DEFAULT NULL,
                ip_hash varchar(128) DEFAULT NULL,
                user_agent_hash varchar(128) DEFAULT NULL,
                metadata_json longtext NULL,
                created_at datetime NOT NULL,
                PRIMARY KEY  (id),
                KEY user_id (user_id),
                KEY method (method),
                KEY result (result),
                KEY created_at (created_at)
            ) {$charset_collate};");
        }

        /**
         * @return array<string,string>
         */
        public static function tables(): array
        {
            global $wpdb;

            return [
                'method_policy' => $wpdb->prefix . 'apfreepass_method_policy',
                'magic_links' => $wpdb->prefix . 'apfreepass_magic_links',
                'sms_challenges' => $wpdb->prefix . 'apfreepass_sms_challenges',
                'passkey_credentials' => $wpdb->prefix . 'apfreepass_passkey_credentials',
                'passkey_challenges' => $wpdb->prefix . 'apfreepass_passkey_challenges',
                'identity_resolvers' => $wpdb->prefix . 'apfreepass_identity_resolvers',
                'login_audit' => $wpdb->prefix . 'apfreepass_login_audit',
            ];
        }
    }
}
