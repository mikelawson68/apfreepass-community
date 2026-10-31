<?php
/**
 * Plugin Name: apFreepass
 * Description: Passwordless sign-in with magic links and optional connector-based SMS delivery.
 * Version: 0.2.4
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

define("APFREEPASS_VERSION", "0.2.4");

if (!function_exists('apfreepass_rp_id')) {
    function apfreepass_rp_id(): string
    {
        $configured = strtolower(trim((string) get_option('apfreepass_rp_id', '')));
        $host = $configured ?: strtolower((string) wp_parse_url(home_url('/'), PHP_URL_HOST));
        return preg_replace('/^www\./', '', $host) ?: 'localhost';
    }
}
define("APFREEPASS_FILE", __FILE__);
define("APFREEPASS_PATH", plugin_dir_path(__FILE__));
define("APFREEPASS_URL", plugin_dir_url(__FILE__));

require_once APFREEPASS_PATH . "includes/class-apfreepass-schema.php";
require_once APFREEPASS_PATH . "includes/class-apfreepass-privacy.php";
APFreepass_Privacy::hooks();
require_once APFREEPASS_PATH . "includes/class-apfreepass-retention.php";
APFreepass_Retention::boot();
register_deactivation_hook(__FILE__, [APFreepass_Retention::class, "deactivate"]);
require_once APFREEPASS_PATH . "includes/class-apfreepass-contract.php";
require_once APFREEPASS_PATH . "includes/class-apfreepass-lifecycle.php";
require_once APFREEPASS_PATH . "includes/class-apfreepass-webauthn.php";
require_once APFREEPASS_PATH . "includes/class-apfreepass-cli.php";

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

if (!function_exists("apfreepass_component")) {
    function apfreepass_component(): array
    {
        return APFreepass_Contract::component();
    }
}

if (!function_exists("apfreepass_contract")) {
    function apfreepass_contract(): array
    {
        return APFreepass_Contract::domain();
    }
}

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
        "rpId" => apfreepass_rp_id(),
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

add_action('admin_init', static function (): void {
    register_setting('apfreepass_signin', 'apfreepass_passkey_enabled', [
        'type' => 'boolean',
        'default' => false,
        'sanitize_callback' => static function ($value): int { return is_scalar($value) && (string) $value === '1' ? 1 : 0; },
    ]);
});
add_action('admin_menu', static function (): void {
    add_options_page('apFreepass Sign-in', 'apFreepass', 'manage_options', 'apfreepass-signin', static function (): void {
        if (!current_user_can('manage_options')) return;
        echo '<div class="wrap"><h1>' . esc_html__('apFreepass Sign-in', 'artistpro-freepass') . '</h1>';
        echo '<form method="post" action="' . esc_url(admin_url('options.php')) . '">';
        settings_fields('apfreepass_signin');
        echo '<input type="hidden" name="apfreepass_passkey_enabled" value="0">';
        echo '<label><input type="checkbox" name="apfreepass_passkey_enabled" value="1" ' . checked((bool) get_option('apfreepass_passkey_enabled', false), true, false) . '> ' . esc_html__('Allow passkey sign-in', 'artistpro-freepass') . '</label>';
        echo '<p class="description">' . esc_html__('Passkeys require HTTPS. Users must sign in first to add a passkey; keep another sign-in method available for recovery.', 'artistpro-freepass') . '</p>';
        submit_button(); echo '</form></div>';
    });
});

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
            'sms_code' => false,
            'passkey' => (bool) get_option('apfreepass_passkey_enabled', false),
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
    function apfreepass_show_login(string $default_redirect = ""): void
    {
        $redirect = apfreepass_login_redirect($default_redirect);
        $nonce = wp_create_nonce("apfreepass_auth");
        $magic_enabled = apfreepass_method_enabled('magic_link');
        $sms_enabled = apfreepass_method_enabled('sms_code') && function_exists('apsms_request_message');
        // Passkeys remain opt-in and require the bundled verifier.
        $passkey_ui_ready = apfreepass_method_enabled('passkey') && class_exists('\\lbuchs\\WebAuthn\\WebAuthn');
        $passkey_first = !$magic_enabled && !$sms_enabled;
        $current_user = wp_get_current_user();

        ob_start();
        ?>
        <div class="apfreepass-login-container">
            <div class="apfreepass-login-form">
                <div class="apfreepass-tabs" role="tablist" aria-label="<?php esc_attr_e("Authentication methods", "artistpro-freepass"); ?>">
                    <?php if ($magic_enabled): ?>
                    <button role="tab" class="apfreepass-tab-btn active" data-tab="magic-link" aria-selected="true">
                        <span class="dashicons dashicons-email-alt"></span>
                        <span><?php esc_html_e("Magic Link", "artistpro-freepass"); ?></span>
                    </button>
                    <?php endif; ?>
                    <?php if ($sms_enabled): ?>
                    <button role="tab" class="apfreepass-tab-btn<?php echo $magic_enabled ? '' : ' active'; ?>" data-tab="sms" aria-selected="<?php echo $magic_enabled ? 'false' : 'true'; ?>">
                        <span class="dashicons dashicons-smartphone"></span>
                        <span><?php esc_html_e("SMS Code", "artistpro-freepass"); ?></span>
                    </button>
                    <?php endif; ?>
                    <?php if ($passkey_ui_ready): ?>
                    <button role="tab" class="apfreepass-tab-btn<?php echo $passkey_first ? ' active' : ''; ?>" data-tab="passkey" aria-selected="<?php echo $passkey_first ? 'true' : 'false'; ?>">
                        <span class="dashicons dashicons-lock"></span>
                        <span><?php esc_html_e("Passkey", "artistpro-freepass"); ?></span>
                    </button>
                    <?php endif; ?>
                </div>

                <div class="apfreepass-auth-panels">
                    <?php if (!$magic_enabled && !$sms_enabled && !$passkey_ui_ready): ?><p><?php esc_html_e('No sign-in method is currently available. Contact the site administrator.', 'artistpro-freepass'); ?></p><?php endif; ?>
                    <?php if ($magic_enabled): ?>
                    <div role="tabpanel" class="apfreepass-tab-panel active" id="tab-magic-link" aria-labelledby="tab-magic-link">
                        <form id="apfreepass-magic-link-form" class="apfreepass-auth-form">
                            <input type="hidden" name="action" value="apfreepass_issue_magic_link">
                            <input type="hidden" name="nonce" value="<?php echo esc_attr($nonce); ?>">
                            <input type="hidden" name="redirect" value="<?php echo esc_attr($redirect); ?>">

                            <div class="form-group">
                                <label for="apfreepass-email"><?php esc_html_e("Email Address", "artistpro-freepass"); ?></label>
                                <input type="email" id="apfreepass-email" name="email" class="form-control"
                                       placeholder="<?php esc_attr_e("Enter your email address", "artistpro-freepass"); ?>" required autocomplete="email">
                            </div>

                            <div class="form-group">
                                <button type="submit" class="btn btn-primary btn-block" id="apfreepass-magic-link-btn">
                                    <span class="btn-text"><?php esc_html_e("Send Magic Link", "artistpro-freepass"); ?></span>
                                    <span class="btn-loading" style="display:none;"><?php esc_html_e("Sending...", "artistpro-freepass"); ?></span>
                                </button>
                            </div>

                            <p class="form-hint"><?php esc_html_e("We'll send a secure magic link to your email. Click the link to sign in instantly.", "artistpro-freepass"); ?></p>

                            <div id="apfreepass-magic-link-message" class="auth-message" style="display:none;"></div>
                        </form>
                    </div>

                    <?php endif; ?>
                    <?php if ($sms_enabled): ?>
                    <div role="tabpanel" class="apfreepass-tab-panel<?php echo $magic_enabled ? '' : ' active'; ?>" id="tab-sms" aria-labelledby="tab-sms"<?php echo $magic_enabled ? ' style="display:none;"' : ''; ?>>
                        <form id="apfreepass-sms-form" class="apfreepass-auth-form">
                            <input type="hidden" name="action" value="apfreepass_issue_sms_challenge">
                            <input type="hidden" name="nonce" value="<?php echo esc_attr($nonce); ?>">
                            <input type="hidden" name="redirect" value="<?php echo esc_attr($redirect); ?>">

                            <div class="form-group">
                                <label for="apfreepass-phone"><?php esc_html_e("Phone Number", "artistpro-freepass"); ?></label>
                                <input type="tel" id="apfreepass-phone" name="phone" class="form-control"
                                       placeholder="<?php esc_attr_e("Enter your phone number (e.g., +1 555-123-4567)", "artistpro-freepass"); ?>" required autocomplete="tel">
                            </div>

                            <div class="form-group">
                                <button type="submit" class="btn btn-primary btn-block" id="apfreepass-sms-btn">
                                    <span class="btn-text"><?php esc_html_e("Send SMS Code", "artistpro-freepass"); ?></span>
                                    <span class="btn-loading" style="display:none;"><?php esc_html_e("Sending...", "artistpro-freepass"); ?></span>
                                </button>
                            </div>

                            <p class="form-hint"><?php esc_html_e("We'll send a 6-digit code via SMS. Standard message rates may apply.", "artistpro-freepass"); ?></p>

                            <div id="apfreepass-sms-message" class="auth-message" style="display:none;"></div>
                        </form>

                        <form id="apfreepass-sms-verify-form" class="apfreepass-auth-form" style="display:none;">
                            <input type="hidden" name="action" value="apfreepass_verify_sms_challenge">
                            <input type="hidden" name="nonce" value="<?php echo esc_attr($nonce); ?>">
                            <input type="hidden" name="redirect" value="<?php echo esc_attr($redirect); ?>">
                            <input type="hidden" name="challenge_id" id="apfreepass-sms-challenge-id">

                            <div class="form-group">
                                <label for="apfreepass-sms-code"><?php esc_html_e("Enter 6-Digit Code", "artistpro-freepass"); ?></label>
                                <input type="text" id="apfreepass-sms-code" name="code" class="form-control"
                                       placeholder="000000" maxlength="6" pattern="\d{6}" required autocomplete="one-time-code" inputmode="numeric">
                            </div>

                            <div class="form-group">
                                <button type="submit" class="btn btn-primary btn-block" id="apfreepass-sms-verify-btn">
                                    <span class="btn-text"><?php esc_html_e("Verify Code", "artistpro-freepass"); ?></span>
                                    <span class="btn-loading" style="display:none;"><?php esc_html_e("Verifying...", "artistpro-freepass"); ?></span>
                                </button>
                            </div>

                            <p class="form-hint"><?php esc_html_e("Code expires in 10 minutes.", "artistpro-freepass"); ?></p>

                            <div id="apfreepass-sms-verify-message" class="auth-message" style="display:none;"></div>
                        </form>
                    </div>

                    <?php endif; ?>
                    <?php if ($passkey_ui_ready): ?>
                    <div role="tabpanel" class="apfreepass-tab-panel<?php echo $passkey_first ? ' active' : ''; ?>" id="tab-passkey"<?php echo $passkey_first ? '' : ' style="display:none;"'; ?>>
                        <?php if (is_user_logged_in()): ?>
                        <div id="apfreepass-passkey-register">
                            <form id="apfreepass-passkey-register-form" class="apfreepass-auth-form">
                                <input type="hidden" id="apfreepass-passkey-reg-username" value="<?php echo esc_attr($current_user->user_login); ?>">
                                <input type="hidden" id="apfreepass-passkey-reg-email" value="<?php echo esc_attr($current_user->user_email); ?>">
                                <label for="apfreepass-passkey-reg-name"><?php esc_html_e('Device name (optional)', 'artistpro-freepass'); ?></label>
                                <input type="text" id="apfreepass-passkey-reg-name" class="form-control">
                                <button type="button" class="btn btn-primary btn-block" id="apfreepass-passkey-register-btn"><span class="btn-text"><?php esc_html_e('Add a passkey', 'artistpro-freepass'); ?></span><span class="btn-loading" style="display:none;"><?php esc_html_e('Creating...', 'artistpro-freepass'); ?></span></button>
                                <p class="form-hint"><?php esc_html_e('Add a passkey to your signed-in account.', 'artistpro-freepass'); ?></p>
                                <div id="apfreepass-passkey-register-message" class="auth-message" style="display:none;"></div>
                            </form>
                            <?php $owned_passkeys = APFreepass_WebAuthn::list_for_user(get_current_user_id()); ?>
                            <?php if ($owned_passkeys): ?>
                            <h3><?php esc_html_e('Your passkeys', 'artistpro-freepass'); ?></h3>
                            <ul class="apfreepass-passkey-list">
                                <?php foreach ($owned_passkeys as $owned_passkey): ?>
                                <li><span><?php echo esc_html($owned_passkey->label ?: __('Passkey', 'artistpro-freepass')); ?></span>
                                    <button type="button" class="apfreepass-passkey-revoke" data-credential-id="<?php echo esc_attr((string) $owned_passkey->id); ?>"><?php esc_html_e('Remove', 'artistpro-freepass'); ?></button></li>
                                <?php endforeach; ?>
                            </ul>
                            <div id="apfreepass-passkey-revoke-message" class="auth-message" style="display:none;"></div>
                            <?php endif; ?>
                        </div>
                        <?php else: ?>
                        <div id="apfreepass-passkey-auth">
                            <form id="apfreepass-passkey-login-form" class="apfreepass-auth-form">
                                <label for="apfreepass-passkey-username"><?php esc_html_e('Username or email', 'artistpro-freepass'); ?></label>
                                <input type="text" id="apfreepass-passkey-username" class="form-control" autocomplete="username" required>
                                <button type="button" class="btn btn-primary btn-block" id="apfreepass-passkey-login-btn"><span class="btn-text"><?php esc_html_e('Sign in with passkey', 'artistpro-freepass'); ?></span><span class="btn-loading" style="display:none;"><?php esc_html_e('Authenticating...', 'artistpro-freepass'); ?></span></button>
                                <p class="form-hint"><?php esc_html_e('Sign in with a passkey already added to your account.', 'artistpro-freepass'); ?></p>
                                <div id="apfreepass-passkey-login-message" class="auth-message" style="display:none;"></div>
                            </form>
                        </div>
                        <?php endif; ?>
                    </div>
                    <?php endif; ?>
                </div>

                <div class="apfreepass-auth-footer">
                    <?php $registration_open = is_multisite() ? in_array(get_site_option('registration'), ['all', 'user'], true) : (bool) get_option('users_can_register'); ?>
                    <?php if ($registration_open): ?>
                    <p>
                        <a href="<?php echo esc_url(wp_registration_url()); ?>"><?php esc_html_e("Create an account", "artistpro-freepass"); ?></a>
                    </p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <?php
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- The template escapes each dynamic value in its context.
        echo ob_get_clean();
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

add_action('wp_ajax_apfreepass_issue_sms_challenge', 'apfreepass_ajax_issue_sms_challenge');
add_action('wp_ajax_nopriv_apfreepass_issue_sms_challenge', 'apfreepass_ajax_issue_sms_challenge');

function apfreepass_ajax_issue_sms_challenge() {
    check_ajax_referer('apfreepass_auth', 'nonce');
    apfreepass_require_method('sms_code');

    $phone = isset($_POST['phone']) ? sanitize_text_field(wp_unslash($_POST['phone'])) : '';
    $redirect = wp_validate_redirect(isset($_POST['redirect']) && is_string($_POST['redirect']) ? esc_url_raw(wp_unslash($_POST['redirect'])) : '', admin_url());

    if (!$phone) {
        wp_send_json_error(['code' => 'invalid_phone', 'message' => __('Please enter a phone number.', 'artistpro-freepass')]);
    }

    // Normalize phone number
    $phone_digits = preg_replace('/[^0-9]/', '', $phone);
    if (strlen($phone_digits) < 10) {
        wp_send_json_error(['code' => 'invalid_phone', 'message' => __('Please enter a valid phone number.', 'artistpro-freepass')]);
    }

    // BOOST stores verified US numbers in E.164 digits (1 + ten-digit number),
    // while volunteers commonly enter the familiar ten-digit form at login.
    if (strlen($phone_digits) === 10) {
        $phone_digits = '1' . $phone_digits;
    }

    // Limit request volume before account lookup, so the response does not
    // depend on whether the supplied phone number belongs to a user.
    $remote = isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
    $limits = [
        'apfreepass_sms_ip_' . hash('sha256', $remote) => 10,
        'apfreepass_sms_phone_' . hash('sha256', $phone_digits) => 3,
    ];
    // Serialize updates across PHP workers; transient increments alone are not atomic.
    global $wpdb;
    $locks = array_map(static fn($key): string => 'apfp_sms_' . substr(hash('sha256', $key), 0, 40), array_keys($limits));
    sort($locks, SORT_STRING);
    $held = [];
    $limit_error = '';
    try {
        foreach ($locks as $lock) {
            if ((string) $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 1)', $lock)) !== '1') {
                $limit_error = 'sms_unavailable';
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
                if (!set_transient($key, (int) get_transient($key) + 1, 15 * MINUTE_IN_SECONDS)) { $limit_error = 'sms_unavailable'; break; }
            }
        }
    } finally {
        foreach (array_reverse($held) as $lock) $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $lock));
    }
    if ($limit_error === 'rate_limited') {
        wp_send_json_error(['code' => $limit_error, 'message' => __('Please wait before requesting another code.', 'artistpro-freepass')], 429);
    }
    if ($limit_error !== '') {
        wp_send_json_error(['code' => $limit_error, 'message' => __('SMS sign-in is temporarily unavailable.', 'artistpro-freepass')], 503);
    }

    // Return an opaque ticket for every well-formed number, including unknown
    // accounts and delivery failures. Never expose the database challenge ID.
    $ticket = bin2hex(random_bytes(32));
    $challenge_id = 0;
    $users = get_users([
        'meta_key' => 'apfreepass_phone',
        'meta_value' => $phone_digits,
        'number' => 2,
    ]);
    // A shared number cannot safely select a single account.
    if (count($users) === 1 && function_exists('apsms_request_message')) {
        $result = APFreepass_Lifecycle::issue_sms_challenge((int) $users[0]->ID, '+' . $phone_digits);
        if (!empty($result['success'])) {
            global $wpdb;
            $tables = APFreepass_Schema::tables();
            // translators: 1: site name, 2: one-time sign-in code.
            $sms_body = sprintf(__('Your %1$s sign-in code is %2$s.', 'artistpro-freepass'), get_bloginfo('name'), $result['code']);
            try {
                $delivery = apsms_request_message([
                    'recipient_number' => '+' . $phone_digits,
                    'body' => $sms_body,
                    'parent_module' => 'apfreepass',
                    'parent_record_id' => (string) $result['sms_challenge_id'],
                    'source_module' => 'apfreepass',
                    'source_record_id' => (string) $result['sms_challenge_id'],
                ]);
            } catch (Throwable $e) {
                $delivery = [];
            }
            $sent = is_array($delivery) && !empty($delivery['success']);
            $values = ['status' => $sent ? 'sent' : 'failed', 'updated_at' => gmdate('Y-m-d H:i:s')];
            if ($sent) $values['delivery_request_ref'] = 'apsms:' . (int) ($delivery['message_id'] ?? 0);
            $saved = $wpdb->update($tables['sms_challenges'], $values, ['id' => $result['sms_challenge_id'], 'status' => 'issued']);
            if ($sent && $saved === 1) $challenge_id = (int) $result['sms_challenge_id'];
        }
    }
    if (!set_transient('apfreepass_sms_ticket_' . hash('sha256', $ticket), $challenge_id, 10 * MINUTE_IN_SECONDS)) {
        wp_send_json_error(['code' => 'sms_unavailable', 'message' => __('SMS sign-in is temporarily unavailable.', 'artistpro-freepass')], 503);
    }
    wp_send_json_success([
        'message' => __('If an account exists, a code has been sent.', 'artistpro-freepass'),
        'challenge_id' => $ticket,
    ]);
}

add_action('wp_ajax_apfreepass_verify_sms_challenge', 'apfreepass_ajax_verify_sms_challenge');
add_action('wp_ajax_nopriv_apfreepass_verify_sms_challenge', 'apfreepass_ajax_verify_sms_challenge');

function apfreepass_ajax_verify_sms_challenge() {
    check_ajax_referer('apfreepass_auth', 'nonce');
    apfreepass_require_method('sms_code');

    $code = isset($_POST['code']) ? sanitize_text_field(wp_unslash($_POST['code'])) : '';
    $ticket = isset($_POST['challenge_id']) && is_string($_POST['challenge_id']) ? sanitize_text_field(wp_unslash($_POST['challenge_id'])) : '';
    $ticket_key = preg_match('/^[a-f0-9]{64}$/', $ticket) ? 'apfreepass_sms_ticket_' . hash('sha256', $ticket) : '';
    $challenge_id = $ticket_key !== '' ? (int) get_transient($ticket_key) : 0;
    $redirect = wp_validate_redirect(isset($_POST['redirect']) && is_string($_POST['redirect']) ? esc_url_raw(wp_unslash($_POST['redirect'])) : '', admin_url());

    if (!$code || !$challenge_id) {
        wp_send_json_error(['code' => 'invalid_code', 'message' => __('The code is invalid or expired.', 'artistpro-freepass')]);
    }

    $result = APFreepass_Lifecycle::verify_sms_challenge($challenge_id, $code);

    if ($result['success']) {
        delete_transient($ticket_key);
        $user_id = $result['user_id'];
        wp_set_current_user($user_id);
        wp_set_auth_cookie($user_id, true);

        wp_send_json_success([
            'message' => __('Code verified! Redirecting...', 'artistpro-freepass'),
            'redirect' => $redirect,
        ]);
    } else {
        wp_send_json_error(['code' => 'invalid_code', 'message' => __('The code is invalid or expired.', 'artistpro-freepass')]);
    }
}

// Retired legacy endpoints never verified WebAuthn assertions or credential ownership.
// Keep explicit errors for old clients instead of allowing an authentication bypass.
foreach (['apfreepass_passkey_authenticate', 'apfreepass_passkey_register', 'apfreepass_passkey_register_complete'] as $apfreepass_retired_action) {
    add_action('wp_ajax_' . $apfreepass_retired_action, 'apfreepass_legacy_passkey_disabled');
    add_action('wp_ajax_nopriv_' . $apfreepass_retired_action, 'apfreepass_legacy_passkey_disabled');
}
function apfreepass_legacy_passkey_disabled(): void {
    wp_send_json_error(['message' => __('This legacy passkey endpoint is no longer supported.', 'artistpro-freepass')], 410);
}

// Magic link verification endpoint
add_action('template_redirect', 'apfreepass_handle_magic_link');

function apfreepass_handle_magic_link() {
    if (!isset($_GET['apfreepass_magic_token'])) {
        return;
    }

    $token = sanitize_text_field(wp_unslash($_GET['apfreepass_magic_token']));

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

// Add identity resolver for CRM phone lookup
add_action('init', function() {
    if (function_exists('APFreepass_Lifecycle')) {
        APFreepass_Lifecycle::create_identity_resolver('crm_optional_contact_phone', 'crm_optional_contact_phone', [
            'crm_table' => 'wp_pubmotor_crm_contacts',
            'phone_field' => 'phone',
            'email_field' => 'email',
        ], true);
    }
}, 20);

// Add rewrite rule for magic link endpoint
add_action('init', function() {
    add_rewrite_rule('^auth/magic-link/?$', 'index.php?apfreepass_magic_link=1', 'top');
    add_rewrite_tag('%apfreepass_magic_link%', '([^&]+)');
});

add_action('template_redirect', function() {
    global $wp_query;
    if (isset($wp_query->query_vars['apfreepass_magic_link'])) {
        if (isset($_GET['apfreepass_magic_token'])) {
            $token = sanitize_text_field(wp_unslash($_GET['apfreepass_magic_token']));
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
