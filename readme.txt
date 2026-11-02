=== apFreepass ===
Contributors: artistpromusic
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 0.3.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Let existing WordPress users sign in with a one-time email link.

== Description ==

apFreepass lets an existing WordPress user request a one-time sign-in link by email. It does not create accounts. Configure a reliable WordPress mail service before relying on it. Requests are rate limited, and the response does not reveal whether an account exists.

This free edition includes email-link sign-in. Passkey and SMS sign-in are available separately in the paid apFreepass edition at https://artistprowp.com/apfreepass/. The paid edition is a separate installation and is not needed for email-link sign-in.

Sign-in records are stored in the WordPress database. Privacy export and erasure tools support relevant sign-in records, including data retained from an earlier edition. Expired challenges are cleaned up by WordPress scheduled tasks. Database advisory locks are required; requests fail safely if locks cannot be obtained.

== Installation ==

1. Back up the site and make sure an administrator has another working login method.
2. Install and activate apFreepass on an individual WordPress site. Network-wide activation is not supported.
3. Place [apfreepass_login] on a page and configure WordPress email delivery.

Do not install the free and paid editions together. Before changing editions, back up and deactivate the existing edition; preserve the database and user records. Older installations that used passkeys or SMS must keep another working login method before changing to the email-only free edition.
