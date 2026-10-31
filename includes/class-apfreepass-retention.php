<?php
/** Expired authentication challenge retention. */
declare(strict_types=1);
defined('ABSPATH') || exit;

final class APFreepass_Retention {
    private const HOOK = 'apfreepass_expired_challenge_cleanup';
    public static function boot(): void {
        add_action('init', [self::class, 'schedule']);
        add_action(self::HOOK, [self::class, 'cleanup']);
    }
    public static function schedule(): void {
        if (!wp_next_scheduled(self::HOOK)) wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::HOOK);
    }
    public static function deactivate(): void { wp_clear_scheduled_hook(self::HOOK); }
    public static function cleanup(): void {
        global $wpdb;
        $tables = APFreepass_Schema::tables();
        $cutoff = gmdate('Y-m-d H:i:s', time() - 30 * DAY_IN_SECONDS);
        foreach (['magic_links', 'sms_challenges', 'passkey_challenges'] as $name) {
            $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE expires_at < %s ORDER BY expires_at LIMIT 500', $tables[$name], $cutoff));
        }
    }
}
