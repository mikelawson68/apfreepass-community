<?php
/**
 * Plugin Name: apFreepass
 * Description: Passwordless email-link sign-in for existing WordPress users.
 * Version: 0.3.2
 * Requires at least: 6.4
 * Requires PHP: 8.0
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Author: artistproWP
 * Text Domain: artistpro-freepass
 */

declare(strict_types=1);

if (!defined("ABSPATH")) {
    exit;
}

// An unpatched older edition can fatal if it is activated after this edition.
// Keep it out of the plugin directory before loading this edition, even when inactive.
if (is_file(WP_PLUGIN_DIR . '/apfreepass/apfreepass.php')) {
    register_activation_hook(__FILE__, static function (): void {
        wp_die(esc_html__('An older apFreepass edition is installed. Back up and move its plugin folder out of the plugins directory before activating this edition; retain the site database and user records.', 'artistpro-freepass'));
    });
    add_action('admin_notices', static function (): void {
        if (current_user_can('activate_plugins')) echo '<div class="notice notice-warning"><p>' . esc_html__('apFreepass is paused because an older edition is still installed. Back up and move the older plugin folder out of the plugins directory; retain the site database and user records.', 'artistpro-freepass') . '</p></div>';
    });
    return;
}

// The older retail edition and this community edition share classes and functions.
$apfreepass_self = plugin_basename(__FILE__);
$apfreepass_active = (array) get_option('active_plugins', []);
if (is_multisite()) $apfreepass_active = array_merge($apfreepass_active, array_keys((array) get_site_option('active_sitewide_plugins', [])));
foreach ($apfreepass_active as $apfreepass_plugin) {
    $apfreepass_folder = explode('/', $apfreepass_plugin, 2)[0];
    if ($apfreepass_plugin !== $apfreepass_self && in_array($apfreepass_folder, ['apfreepass', 'artistpro-freepass'], true)) {
        register_activation_hook(__FILE__, static function (): void { wp_die(esc_html__('Deactivate the other apFreepass edition first. Existing accounts and settings remain on the site.', 'artistpro-freepass')); });
        add_action('admin_notices', static function (): void { if (current_user_can('activate_plugins')) echo '<div class="notice notice-warning"><p>' . esc_html__('This apFreepass edition is paused because another edition is active.', 'artistpro-freepass') . '</p></div>'; });
        return;
    }
}
// Conditional declarations prevent a PHP fatal when another edition is already loaded.
if (!function_exists('apfreepass_login_redirect')) {

define("APFREEPASS_VERSION", "0.3.2");

// Store edition only: WordPress.org builds must not include this update hook.
define("APFREEPASS_FILE", __FILE__);
define("APFREEPASS_PATH", plugin_dir_path(__FILE__));
define("APFREEPASS_URL", plugin_dir_url(__FILE__));

require_once APFREEPASS_PATH . "includes/class-apfreepass-schema.php";
require_once APFREEPASS_PATH . "includes/class-apfreepass-privacy.php";
APFreepass_Privacy::hooks();
require_once APFREEPASS_PATH . "includes/class-apfreepass-retention.php";
APFreepass_Retention::boot();
register_deactivation_hook(__FILE__, [APFreepass_Retention::class, "deactivate"]);
require_once APFREEPASS_PATH . "includes/class-apfreepass-lifecycle.php";

/** Record this edition's default for a subsequent paid-edition switch. */
function apfreepass_record_community_redirect(): void {
    if (get_option('apfreepass_redirect_mode', false) !== 'wordpress') {
        update_option('apfreepass_redirect_mode', 'wordpress', false);
    }
}
add_action('plugins_loaded', 'apfreepass_record_community_redirect');

register_activation_hook(__FILE__, static function ($network_wide): void {
    if (is_multisite() && $network_wide) {
        wp_die(esc_html__('Activate apFreepass on each individual site instead of network-wide.', 'artistpro-freepass'));
    }
    apfreepass_record_community_redirect();
    APFreepass_Schema::install();
});

function apfreepass_login_redirect(string $default_redirect = ""): string {
    $fallback = $default_redirect !== "" ? wp_validate_redirect($default_redirect, admin_url()) : admin_url();
    $requested = isset($_GET["redirect_to"]) && is_string($_GET["redirect_to"]) ? esc_url_raw(wp_unslash($_GET["redirect_to"])) : '';
    return wp_validate_redirect($requested ?: $fallback, $fallback);
}

function apfreepass_enqueue_auth_assets(string $default_redirect = ""): void {
    wp_enqueue_style("apfreepass-auth", APFREEPASS_URL . "assets/css/auth.css", [], APFREEPASS_VERSION);
    wp_enqueue_script("apfreepass-auth", APFREEPASS_URL . "assets/js/auth.js", ["jquery"], APFREEPASS_VERSION, true);
    wp_localize_script("apfreepass-auth", "apfreepassAuth", [
        "ajaxurl" => admin_url("admin-ajax.php"),
        "nonce" => wp_create_nonce("apfreepass_auth"),
        "redirect" => apfreepass_login_redirect($default_redirect),
        "siteName" => get_bloginfo("name"),
    ]);
}

add_action("wp_enqueue_scripts", function(): void {
    global $post;
    if (is_page("crm") || is_page("dashboard") || is_page("login") || is_page("login-form") || ($post instanceof WP_Post && has_shortcode($post->post_content, 'apfreepass_login'))) {
        apfreepass_enqueue_auth_assets();
    }
});

add_action("wp_enqueue_scripts", function(): void {
    wp_enqueue_style("apfreepass-base", APFREEPASS_URL . "assets/css/base.css", [], APFREEPASS_VERSION);
}, 5);

if (!function_exists("apfreepass_is_authenticated")) {
    function apfreepass_is_authenticated(): bool
    {
        return is_user_logged_in();
    }
}

if (!function_exists('apfreepass_method_enabled')) {
    function apfreepass_method_enabled(string $method): bool
    {
        $defaults = [
            'magic_link' => true,
        ];

        return (bool) apply_filters(
            'apfreepass_method_enabled',
            $defaults[$method] ?? false,
            $method
        );
    }
}

if (!function_exists('apfreepass_require_method')) {
    function apfreepass_require_method(string $method): void
    {
        if (!apfreepass_method_enabled($method)) {
            wp_send_json_error([
                'code' => 'method_unavailable',
                'message' => __('This sign-in method is not available yet.', 'artistpro-freepass'),
            ], 503);
        }
    }
}

if (!function_exists("apfreepass_show_login")) {
    function apfreepass_show_login(string $default_redirect = ""): void {
        if (!apfreepass_method_enabled('magic_link')) { echo '<p>'.esc_html__('Sign-in is unavailable. Contact the site administrator.','artistpro-freepass').'</p>'; return; }
        $redirect=apfreepass_login_redirect($default_redirect); $nonce=wp_create_nonce('apfreepass_auth');
        echo '<div class="apfreepass-login-container"><div class="apfreepass-login-form"><h2>'.esc_html__('Sign in by email','artistpro-freepass').'</h2><form id="apfreepass-magic-link-form" class="apfreepass-auth-form">';
        echo '<input type="hidden" name="action" value="apfreepass_issue_magic_link"><input type="hidden" name="nonce" value="'.esc_attr($nonce).'"><input type="hidden" name="redirect" value="'.esc_attr($redirect).'">';
        echo '<label for="apfreepass-email">'.esc_html__('Email address','artistpro-freepass').'</label><input type="email" id="apfreepass-email" name="email" autocomplete="email" required><button type="submit" id="apfreepass-magic-link-btn">'.esc_html__('Send sign-in link','artistpro-freepass').'</button><p id="apfreepass-magic-link-message" role="status" aria-live="polite"></p></form></div></div>';
    }
}

add_shortcode('apfreepass_login', static function (): string {
    apfreepass_enqueue_auth_assets(admin_url());
    ob_start();
    apfreepass_show_login(admin_url());
    return (string) ob_get_clean();
});

if (!function_exists("apfreepass_get_login_url")) {
    function apfreepass_get_login_url(string $redirect = ""): string
    {
        return wp_login_url($redirect ?: admin_url());
    }
}

if (!function_exists("apfreepass_get_register_url")) {
    function apfreepass_get_register_url(string $redirect = ""): string
    {
        return wp_registration_url($redirect ?: admin_url());
    }
}

// AJAX Handlers for passwordless authentication
add_action('wp_ajax_apfreepass_issue_magic_link', 'apfreepass_ajax_issue_magic_link');
add_action('wp_ajax_nopriv_apfreepass_issue_magic_link', 'apfreepass_ajax_issue_magic_link');

function apfreepass_ajax_issue_magic_link() {
    check_ajax_referer('apfreepass_auth', 'nonce');
    apfreepass_require_method('magic_link');

    $email = isset($_POST['email']) && is_string($_POST['email']) ? sanitize_email(wp_unslash($_POST['email'])) : '';
    $redirect = wp_validate_redirect(isset($_POST['redirect']) && is_string($_POST['redirect']) ? esc_url_raw(wp_unslash($_POST['redirect'])) : '', admin_url());

    if (!$email || !is_email($email)) {
        wp_send_json_error(['code' => 'invalid_email', 'message' => __('Please enter a valid email address.', 'artistpro-freepass')]);
    }

    // Bound recipient and IP before account lookup, including across concurrent workers.
    $remote = isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
    $limits = [
        'apfreepass_magic_ip_' . hash('sha256', $remote) => 20,
        'apfreepass_magic_email_' . hash('sha256', strtolower($email)) => 5,
    ];
    global $wpdb;
    $locks = array_map(static fn($key): string => 'apfp_magic_' . substr(hash('sha256', $key), 0, 40), array_keys($limits));
    sort($locks, SORT_STRING);
    $held = [];
    $limit_error = '';
    try {
        foreach ($locks as $lock) {
            if ((string) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 1)', $lock)) !== '1') {
                $limit_error = 'magic_unavailable';
                break;
            }
            $held[] = $lock;
        }
        if ($limit_error === '') {
            foreach ($limits as $key => $limit) {
                if ((int) get_transient($key) >= $limit) { $limit_error = 'rate_limited'; break; }
            }
        }
        if ($limit_error === '') {
            foreach ($limits as $key => $limit) {
                if (!set_transient($key, (int) get_transient($key) + 1, 15 * MINUTE_IN_SECONDS)) { $limit_error = 'magic_unavailable'; break; }
            }
        }
    } finally {
        foreach (array_reverse($held) as $lock) $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
    }
    if ($limit_error === 'rate_limited') {
        wp_send_json_error(['code' => $limit_error, 'message' => __('Please wait before requesting another sign-in link.', 'artistpro-freepass')], 429);
    }
    if ($limit_error !== '') {
        wp_send_json_error(['code' => $limit_error, 'message' => __('Sign-in is temporarily unavailable.', 'artistpro-freepass')], 503);
    }

    // Sign-in never creates accounts. Registration is managed separately by
    // the site, and the response must not disclose whether an account exists.
    $user = get_user_by('email', $email);
    if (!$user) {
        wp_send_json_success(['message' => __('If an account exists, a sign-in link has been sent.', 'artistpro-freepass')]);
    }

    // Issue magic link
    $result = APFreepass_Lifecycle::issue_magic_link($user->ID, $email, $redirect);

    if ($result['success']) {
        // Send the magic link email
        $send_result = APFreepass_Lifecycle::send_magic_link_email(
            $result['magic_link_id'],
            $result['token'],
            $email,
            $redirect
        );

        // Do not expose account existence through transport errors.
        wp_send_json_success(['message' => __('If an account exists, a sign-in link has been sent.', 'artistpro-freepass')]);
    } else {
        // Do not reveal account existence if the storage operation fails.
        wp_send_json_success(['message' => __('If an account exists, a sign-in link has been sent.', 'artistpro-freepass')]);
    }
}

// The signed-in session is created only after a one-time emailed token is checked.
// A WordPress nonce cannot be required on a link opened from a user's email.
function apfreepass_request_magic_token(): string {
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a one-time bearer token from email, validated below and consumed by the lifecycle service.
    $raw = isset($_GET['apfreepass_magic_token']) && is_string($_GET['apfreepass_magic_token']) ? wp_unslash($_GET['apfreepass_magic_token']) : '';
    return preg_match('/^[a-f0-9]{64}$/D', $raw) ? $raw : '';
}

// Magic link verification endpoint
add_action('template_redirect', 'apfreepass_handle_magic_link');

function apfreepass_handle_magic_link() {
    if (!isset($_GET['apfreepass_magic_token'])) {
        return;
    }

    $token = apfreepass_request_magic_token();

    $result = APFreepass_Lifecycle::handle_magic_link_verification($token);

    if ($result['success']) {
        wp_safe_redirect($result['redirect']);
        exit;
    } else {
        // Show error page
        wp_die('<div class="apfreepass-error-container"><h1>' . esc_html__('Invalid Magic Link', 'artistpro-freepass') . '</h1>
            <p>' . esc_html__('This magic link is invalid, expired, or has already been used.', 'artistpro-freepass') . '</p>
            <p><a href="' . esc_url(wp_login_url()) . '" class="button button-primary">' . esc_html__('Try Again', 'artistpro-freepass') . '</a></p></div>',
            esc_html__('Invalid Magic Link', 'artistpro-freepass'),
            ['response' => 400]);
    }
}

// Add rewrite rule for magic link endpoint
add_action('init', function() {
    add_rewrite_rule('^auth/magic-link/?$', 'index.php?apfreepass_magic_link=1', 'top');
    add_rewrite_tag('%apfreepass_magic_link%', '([^&]+)');
});

add_action('template_redirect', function() {
    global $wp_query;
    if (isset($wp_query->query_vars['apfreepass_magic_link'])) {
        if (isset($_GET['apfreepass_magic_token'])) {
            $token = apfreepass_request_magic_token();
            $result = APFreepass_Lifecycle::handle_magic_link_verification($token);

            if ($result['success']) {
                wp_safe_redirect($result['redirect']);
                exit;
            }
        }
        wp_die(esc_html__('Invalid or expired magic link.', 'artistpro-freepass'), '', ['response' => 400]);
    }
});

} // End conditional community edition bootstrap.
