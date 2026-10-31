=== apFreepass ===
Contributors: artistpromusic
Tags: authentication, passwordless, passkeys, login
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 0.2.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Sign in to existing WordPress accounts using email magic links and optional passkeys.

== Description ==

apFreepass provides a sign-in form for existing accounts. Add the [apfreepass_login] shortcode to a page. Email links are single-use and use your site's configured WordPress mail delivery. Passkeys are off by default; administrators can enable them in Settings > apFreepass. Users sign in first to add a passkey and can remove their own passkeys. Keep another sign-in method available for account recovery.

SMS sign-in is optional and requires a separately configured compatible SMS connector. This plugin does not include an SMS service or transmit SMS by itself. Your chosen connector and provider handle any messages and may have their own terms and charges. Magic-link and SMS request limits require database advisory locks; if the database does not support them, those sign-in methods remain unavailable.

The plugin stores sign-in challenge records, account IDs, email addresses associated with magic links, passkey public credentials, and authentication audit information in the site's database. The site owner is responsible for the privacy notice and for configuring their mail and optional SMS providers. No commercial license or artistpro account is required. WordPress Tools > Export Personal Data can export apFreepass records, and Tools > Erase Personal Data can remove them; removing passkeys makes them unusable. Process requests before deleting the related WordPress account so its other sign-in records can be identified. This does not remove records held by mail or SMS providers. Expired sign-in challenges are removed after 30 days by a daily scheduled task, up to 500 per challenge type each day. Passkeys and the sign-in audit are not removed by that task.

This package includes the lbuchs/webauthn library by Lukas Buchs and contributors under the MIT license; its license is included in vendor/lbuchs/webauthn/LICENSE. Composer's autoload files include their MIT license in vendor/composer/LICENSE.

== Installation ==

If an older apFreepass edition is installed, back up and move its plugin folder out of the plugins directory before activating this edition. Keep the site database and user records. Upload and activate the plugin on an individual WordPress site. On multisite, activate it separately for each site; network-wide activation is not supported. Add [apfreepass_login] to a page. Configure reliable WordPress mail delivery before using magic links. To use passkeys, enable them in Settings > apFreepass and serve the site over HTTPS.

== Frequently Asked Questions ==

= Does a magic link create an account? =

No. It signs in an existing account. Registration is managed by the site's normal registration settings.

= What happens if a passkey is lost? =

Use another available sign-in method, such as an email magic link, to sign in and remove the lost passkey. Keep a working recovery method before relying on passkeys.

== Changelog ==

= 0.2.4 =
* Preserve the WordPress sign-in destination when moving to the paid edition.

= 0.2.3 =
* Prepare the community package with magic links and optional passkeys.
