# apFreepass

Passwordless sign-in for existing WordPress accounts using email magic links, optional passkeys, and an optional SMS connector. Your site keeps its own accounts and authentication records.

## Install

- WordPress 6.4 or newer and PHP 8.0 or newer are required.
- Download the free store edition from [artistproWP](https://artistprowp.com/apfreepass/), upload its ZIP in WordPress, and activate it.
- Add the `[apfreepass_login]` shortcode to a page. Magic links use your site's WordPress mail service and sign in existing users; normal WordPress registration creates new accounts.
- Enable passkeys in Settings > apFreepass if desired. Use HTTPS, sign in before registering a passkey, and keep a separate recovery method.
- SMS sign-in requires a separately configured compatible connector and may incur provider charges. Shared phone numbers are not used to select an account.

This repository contains the free community source without the store updater. The free store ZIP has a separate update channel; WordPress.org distribution, if approved, uses its own updates. Do not activate more than one edition at a time. Deactivate the free edition before uploading the paid edition and retain another administrator sign-in method during the change.

## Support and paid edition

The free edition is GPL-2.0-or-later. A paid edition with support and paid-edition updates is available at [artistproWP](https://artistprowp.com/apfreepass/). Provider services such as SMS are separate.

## Privacy and security

Sign-in challenge records, public passkey credentials, and authentication audit information are stored on the site. WordPress personal-data export and erasure tools support relevant apFreepass records. Review your privacy notice and keep WordPress and PHP current. Please report security issues privately via [artistproWP support](https://artistprowp.com/support/) rather than posting credentials or exploit details in a public issue.

## License

GPL-2.0-or-later; see [LICENSE.txt](LICENSE.txt). The bundled lbuchs/webauthn and Composer components include their MIT licenses in their respective vendor directories.
