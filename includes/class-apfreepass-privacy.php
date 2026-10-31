<?php
/** WordPress personal-data erasure for apFreepass records. */
if (!defined('ABSPATH')) exit;
final class APFreepass_Privacy {
    public static function hooks(): void {
        add_filter('wp_privacy_personal_data_exporters', static function (array $exporters): array {
            $exporters['apfreepass'] = ['exporter_friendly_name' => __('apFreepass sign-in data', 'artistpro-freepass'), 'callback' => [self::class, 'export']];
            return $exporters;
        });
        add_filter('wp_privacy_personal_data_erasers', static function (array $erasers): array {
            $erasers['apfreepass'] = ['eraser_friendly_name' => __('apFreepass sign-in data', 'artistpro-freepass'), 'callback' => [self::class, 'erase']];
            return $erasers;
        });
    }
    /** Export a bounded page without exposing active token hashes or private keys. */
    public static function export(string $email, int $page = 1): array {
        global $wpdb;
        $email = sanitize_email($email); $page = max(1, $page); $limit = 50; $offset = ($page - 1) * $limit;
        $result = ['data' => [], 'done' => true];
        if (!is_email($email)) return $result;
        $user = get_user_by('email', $email); $user_id = $user ? (int) $user->ID : 0;
        $tables = APFreepass_Schema::tables();
        $queries = [
            'magic_links' => $wpdb->prepare('SELECT id, email, status, created_at, expires_at, used_at FROM %i WHERE email = %s OR (%d > 0 AND user_id = %d) ORDER BY id LIMIT %d OFFSET %d', $tables['magic_links'], $email, $user_id, $user_id, $limit, $offset),
            'login_audit' => $wpdb->prepare("SELECT id, method, result, reason, ip_hash, user_agent_hash, metadata_json, created_at FROM %i WHERE (%d > 0 AND user_id = %d) OR (JSON_VALID(metadata_json) AND JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.email')) = %s) ORDER BY id LIMIT %d OFFSET %d", $tables['login_audit'], $user_id, $user_id, $email, $limit, $offset),
        ];
        if ($user_id) {
            $queries['sms_challenges'] = $wpdb->prepare('SELECT id, phone_e164, status, created_at, expires_at, verified_at FROM %i WHERE user_id = %d ORDER BY id LIMIT %d OFFSET %d', $tables['sms_challenges'], $user_id, $limit, $offset);
            $queries['passkey_credentials'] = $wpdb->prepare('SELECT id, credential_id, rp_id, label, status, sign_count, created_at, last_used_at FROM %i WHERE user_id = %d ORDER BY id LIMIT %d OFFSET %d', $tables['passkey_credentials'], $user_id, $limit, $offset);
            $queries['passkey_challenges'] = $wpdb->prepare('SELECT id, challenge_type, rp_id, origin, status, created_at, expires_at, verified_at FROM %i WHERE user_id = %d ORDER BY id LIMIT %d OFFSET %d', $tables['passkey_challenges'], $user_id, $limit, $offset);
        }
        foreach ($queries as $name => $query) {
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Each query is prepared above with identifier and value placeholders.
            $rows = $wpdb->get_results($query, ARRAY_A);
            if ($wpdb->last_error || !is_array($rows)) {
                $result['data'][] = ['group_id' => 'apfreepass', 'group_label' => __('apFreepass sign-in data', 'artistpro-freepass'), 'item_id' => 'apfreepass-export-error-' . $name, 'data' => [['name' => __('Export status', 'artistpro-freepass'), 'value' => __('Some records could not be exported. Ask the site administrator to retry.', 'artistpro-freepass')]]];
                continue;
            }
            if (count($rows) === $limit) $result['done'] = false;
            foreach ($rows as $row) {
                $id = (int) $row['id']; unset($row['id']); $fields = [];
                foreach ($row as $key => $value) if ($value !== null && $value !== '') $fields[] = ['name' => ucwords(str_replace('_', ' ', $key)), 'value' => (string) $value];
                $result['data'][] = ['group_id' => 'apfreepass', 'group_label' => __('apFreepass sign-in data', 'artistpro-freepass'), 'item_id' => 'apfreepass-' . $name . '-' . $id, 'data' => $fields];
            }
        }
        if ($user_id && $page === 1 && metadata_exists('user', $user_id, 'apfreepass_phone')) {
            $result['data'][] = ['group_id' => 'apfreepass', 'group_label' => __('apFreepass sign-in data', 'artistpro-freepass'), 'item_id' => 'apfreepass-phone-' . $user_id, 'data' => [['name' => __('Phone number', 'artistpro-freepass'), 'value' => (string) get_user_meta($user_id, 'apfreepass_phone', true)]]];
        }
        return $result;
    }

    /** Remove a bounded batch; later pages continue with the remaining rows. */
    public static function erase(string $email, int $page = 1): array {
        global $wpdb;
        $email = sanitize_email($email);
        $result = ['items_removed' => false, 'items_retained' => false, 'messages' => [], 'done' => true];
        if (!is_email($email)) return $result;
        $user = get_user_by('email', $email); $user_id = $user ? (int) $user->ID : 0;
        $tables = APFreepass_Schema::tables(); $limit = 100;
        $queries = [
            'magic_links' => $wpdb->prepare('SELECT id FROM %i WHERE email = %s OR (%d > 0 AND user_id = %d) ORDER BY id LIMIT %d', $tables['magic_links'], $email, $user_id, $user_id, $limit),
            'login_audit' => $wpdb->prepare("SELECT id FROM %i WHERE (%d > 0 AND user_id = %d) OR (JSON_VALID(metadata_json) AND JSON_UNQUOTE(JSON_EXTRACT(metadata_json, '$.email')) = %s) ORDER BY id LIMIT %d", $tables['login_audit'], $user_id, $user_id, $email, $limit),
        ];
        if ($user_id) foreach (['sms_challenges', 'passkey_credentials', 'passkey_challenges'] as $name) {
            $queries[$name] = $wpdb->prepare('SELECT id FROM %i WHERE user_id = %d ORDER BY id LIMIT %d', $tables[$name], $user_id, $limit);
        }
        foreach ($queries as $name => $query) {
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Every query in this list is prepared above with identifier and value placeholders.
            $ids = $wpdb->get_col($query);
            if ($wpdb->last_error || !is_array($ids)) {
                $result['items_retained'] = true;
                $result['messages'][] = __('Some apFreepass data could not be located. Retry the request.', 'artistpro-freepass');
                continue;
            }
            if (count($ids) === $limit) $result['done'] = false;
            foreach ($ids as $id) {
                $deleted = $wpdb->delete($tables[$name], ['id' => (int) $id]);
                if ($deleted === false) {
                    $result['items_retained'] = true;
                    $result['messages'][] = __('Some apFreepass data could not be removed. Retry the request.', 'artistpro-freepass');
                } elseif ($deleted > 0) $result['items_removed'] = true;
            }
        }
        if ($user_id && metadata_exists('user', $user_id, 'apfreepass_phone')) {
            if (delete_user_meta($user_id, 'apfreepass_phone')) $result['items_removed'] = true;
            else { $result['items_retained'] = true; $result['messages'][] = __('The apFreepass phone number could not be removed.', 'artistpro-freepass'); }
        }
        if ($result['items_removed']) $result['messages'][] = __('apFreepass sign-in records were removed. Passkeys removed by this request can no longer be used.', 'artistpro-freepass');
        return $result;
    }
}
