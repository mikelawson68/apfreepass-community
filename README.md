# apFreepass — email-link sign-in for WordPress

apFreepass lets existing WordPress users sign in with a one-time email link. This repository contains the **free email-link edition**, licensed GPL-2.0-or-later.

[Download the free plugin from artistproWP](https://artistprowp.com/apfreepass/) · [Explore paid passkeys, SMS, support and updates](https://artistprowp.com/apfreepass/#plans) · [Support](https://artistprowp.com/support/)

## Free and paid

- **Free:** email-link sign-in for existing accounts. Configure your own WordPress email delivery.
- **Paid:** a separate apFreepass edition adds passkeys and SMS sign-in and includes one year of support and updates. SMS requires the free Twilio connector and your own Twilio account; Twilio may charge separately.

Install one edition at a time. Before switching, back up your site, keep another administrator sign-in method available, deactivate the old edition and move its plugin folder out of the WordPress plugins directory. Preserve the WordPress database and user records.

Older free releases included passkeys and SMS. Their GPL history remains available; the current free edition provides email-link sign-in only.

## Installation

1. Download the ZIP from the product page and install it in WordPress.
2. Configure reliable WordPress email delivery.
3. Add `[apfreepass_login]` to a page. The user must already have a WordPress account.

Requires WordPress 6.4 or later and PHP 8.0 or later. See `readme.txt` for additional details.
