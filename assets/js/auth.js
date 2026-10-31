/**
 * apFreepass Authentication JavaScript
 * Handles passwordless authentication UI interactions
 */
(function($) {
    'use strict';

    var apfreepassAuth = window.apfreepassAuth || {};
    var ajaxurl = apfreepassAuth.ajaxurl || ajaxurl;
    var nonce = apfreepassAuth.nonce || '';
    var redirect = apfreepassAuth.redirect || '';
    var rpId = apfreepassAuth.rpId || window.location.hostname;
    var siteName = apfreepassAuth.siteName || document.title;
    var i18n = apfreepassAuth.i18n || {};

    // State
    var state = {
        currentTab: 'magic-link',
        passkeyMode: 'login', // 'login' or 'register'
        smsChallengeId: null,
        passkeyChallengeId: null,
    };

    // DOM elements
    var $container = null;
    var $tabButtons = null;
    var $tabPanels = null;

    function init() {
        $container = $('.apfreepass-login-container');
        if (!$container.length) return;

        $tabButtons = $container.find('.apfreepass-tab-btn');
        $tabPanels = $container.find('.apfreepass-tab-panel');

        bindTabSwitching();
        bindMagicLinkForm();
        bindSMSForms();
        bindPasskeyForms();
        bindPasskeyRevocation();
        bindPasskeyModeToggle();
        initPasskeySupport();
    }

    function bindTabSwitching() {
        $tabButtons.on('click', function(e) {
            e.preventDefault();
            var $btn = $(this);
            var tab = $btn.data('tab');

            if ($btn.hasClass('active')) return;

            $tabButtons.removeClass('active').attr('aria-selected', 'false');
            $btn.addClass('active').attr('aria-selected', 'true');

            $tabPanels.removeClass('active').hide();
            $('#tab-' + tab).addClass('active').show();

            state.currentTab = tab;

            // Clear messages when switching tabs
            clearAllMessages();
        });
    }

    function bindMagicLinkForm() {
        $('#apfreepass-magic-link-form').on('submit', function(e) {
            e.preventDefault();
            var $form = $(this);
            var $btn = $form.find('#apfreepass-magic-link-btn');
            var email = $form.find('#apfreepass-email').val().trim();

            if (!email || !isValidEmail(email)) {
                showMessage('#apfreepass-magic-link-message', i18n.invalidEmail || 'Please enter a valid email address.', 'error');
                return;
            }

            setLoading($btn, true);
            clearMessage('#apfreepass-magic-link-message');

            $.ajax({
                url: ajaxurl,
                method: 'POST',
                data: $form.serialize(),
                success: function(response) {
                    if (response.success) {
                        showMessage('#apfreepass-magic-link-message',
                            i18n.magicLinkSent || 'Magic link sent! Check your email.', 'success');
                        $form[0].reset();
                    } else {
                        showMessage('#apfreepass-magic-link-message',
                            response.data?.message || i18n.error || 'An error occurred. Please try again.', 'error');
                    }
                },
                error: function() {
                    showMessage('#apfreepass-magic-link-message',
                        i18n.error || 'An error occurred. Please try again.', 'error');
                },
                complete: function() {
                    setLoading($btn, false);
                }
            });
        });
    }

    function bindSMSForms() {
        // Send SMS code
        $('#apfreepass-sms-form').on('submit', function(e) {
            e.preventDefault();
            var $form = $(this);
            var $btn = $form.find('#apfreepass-sms-btn');
            var phone = $form.find('#apfreepass-phone').val().trim();

            if (!phone) {
                showMessage('#apfreepass-sms-message', i18n.invalidPhone || 'Please enter a phone number.', 'error');
                return;
            }

            setLoading($btn, true);
            clearMessage('#apfreepass-sms-message');

            $.ajax({
                url: ajaxurl,
                method: 'POST',
                data: $form.serialize(),
                success: function(response) {
                    if (response.success) {
                        state.smsChallengeId = response.data?.challenge_id || response.data?.sms_challenge_id;
                        if (!state.smsChallengeId) {
                            showMessage('#apfreepass-sms-message',
                                'The code was sent, but the sign-in form could not continue. Please request a new code.', 'error');
                            return;
                        }
                        $('#apfreepass-sms-challenge-id').val(state.smsChallengeId);
                        $form.hide();
                        var $verifyForm = $('#apfreepass-sms-verify-form');
                        $verifyForm.css('display', 'block').show();
                        showMessage('#apfreepass-sms-verify-message',
                            i18n.smsCodeSent || 'SMS code sent! Enter the 6-digit code.', 'success');
                        $('#apfreepass-sms-code').trigger('focus');
                        if ($verifyForm[0]) {
                            $verifyForm[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
                        }
                    } else {
                        showMessage('#apfreepass-sms-message',
                            response.data?.message || i18n.error || 'An error occurred. Please try again.', 'error');
                    }
                },
                error: function() {
                    showMessage('#apfreepass-sms-message',
                        i18n.error || 'An error occurred. Please try again.', 'error');
                },
                complete: function() {
                    setLoading($btn, false);
                }
            });
        });

        // Verify SMS code
        $('#apfreepass-sms-verify-form').on('submit', function(e) {
            e.preventDefault();
            var $form = $(this);
            var $btn = $form.find('#apfreepass-sms-verify-btn');
            var code = $form.find('#apfreepass-sms-code').val().trim();

            if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
                showMessage('#apfreepass-sms-verify-message', i18n.invalidCode || 'Please enter a valid 6-digit code.', 'error');
                return;
            }

            setLoading($btn, true);
            clearMessage('#apfreepass-sms-verify-message');

            $.ajax({
                url: ajaxurl,
                method: 'POST',
                data: $form.serialize(),
                success: function(response) {
                    if (response.success) {
                        showMessage('#apfreepass-sms-verify-message',
                            i18n.codeVerified || 'Code verified! Redirecting...', 'success');
                        setTimeout(function() {
                            window.location.href = response.data?.redirect || redirect || apfreepassAuth.redirect || '/';
                        }, 1500);
                    } else {
                        showMessage('#apfreepass-sms-verify-message',
                            response.data?.message || i18n.invalidCode || 'Invalid code. Please try again.', 'error');
                    }
                },
                error: function() {
                    showMessage('#apfreepass-sms-verify-message',
                        i18n.error || 'An error occurred. Please try again.', 'error');
                },
                complete: function() {
                    setLoading($btn, false);
                }
            });
        });
    }

    function bindPasskeyForms() {
        // Passkey login (authentication)
        $('#apfreepass-passkey-login-btn').on('click', function() {
            if (!window.PublicKeyCredential) {
                showMessage('#apfreepass-passkey-login-message',
                    i18n.passkeyNotSupported || 'Passkeys are not supported on this device/browser.', 'error');
                return;
            }

            var $btn = $(this);
            var username = $('#apfreepass-passkey-username').val().trim();

            setLoading($btn, true);
            clearMessage('#apfreepass-passkey-login-message');

            // Get challenge from server
            $.ajax({
                url: ajaxurl,
                method: 'POST',
                data: {
                    action: 'apfreepass_passkey_get_challenge',
                    nonce: nonce,
                    username: username,
                },
                success: function(response) {
                    if (!response.success) {
                        showMessage('#apfreepass-passkey-login-message',
                            response.data?.message || i18n.error || 'An error occurred.', 'error');
                        setLoading($btn, false);
                        return;
                    }

                    var challenge = base64urlToBuffer(response.data.challenge);
                    state.passkeyChallengeId = response.data.challenge_id;
                    var allowCredentials = response.data.credentials?.map(function(cred) {
                        return {
                            type: 'public-key',
                            id: base64urlToBuffer(cred.credential_id),
                            transports: cred.transports ? JSON.parse(cred.transports) : ['internal', 'hybrid']
                        };
                    }) || [];

                    var options = {
                        publicKey: {
                            challenge: challenge,
                            allowCredentials: allowCredentials,
                            timeout: 60000,
                            rpId: rpId,
                            userVerification: 'required',
                        }
                    };

                    navigator.credentials.get(options)
                        .then(function(credential) {
                            return verifyPasskeyAssertion(credential);
                        })
                        .catch(function(err) {
                            if (err.name === 'NotAllowedError') {
                                showMessage('#apfreepass-passkey-login-message',
                                    i18n.passkeyCancelled || 'Authentication was cancelled.', 'error');
                            } else if (err.name === 'NotFoundError') {
                                showMessage('#apfreepass-passkey-login-message',
                                    i18n.noPasskeyFound || 'No passkey found for this device.', 'error');
                            } else {
                                showMessage('#apfreepass-passkey-login-message',
                                    i18n.passkeyError || 'Passkey authentication failed. Please try again.', 'error');
                            }
                            setLoading($btn, false);
                        });
                },
                error: function() {
                    showMessage('#apfreepass-passkey-login-message',
                        i18n.error || 'An error occurred. Please try again.', 'error');
                    setLoading($btn, false);
                }
            });
        });

        // Passkey registration
        $('#apfreepass-passkey-register-btn').on('click', function() {
            if (!window.PublicKeyCredential) {
                showMessage('#apfreepass-passkey-register-message',
                    i18n.passkeyNotSupported || 'Passkeys are not supported on this device/browser.', 'error');
                return;
            }

            var $btn = $(this);
            var $form = $('#apfreepass-passkey-register-form');
            var username = $form.find('#apfreepass-passkey-reg-username').val().trim();
            var email = $form.find('#apfreepass-passkey-reg-email').val().trim();
            var deviceName = $form.find('#apfreepass-passkey-reg-name').val().trim();

            if (!username) {
                showMessage('#apfreepass-passkey-register-message', 'Please enter a username.', 'error');
                return;
            }

            if (!email || !isValidEmail(email)) {
                showMessage('#apfreepass-passkey-register-message', 'Please enter a valid email.', 'error');
                return;
            }

            setLoading($btn, true);
            clearMessage('#apfreepass-passkey-register-message');

            // Get challenge and create credential
            $.ajax({
                url: ajaxurl,
                method: 'POST',
                data: {
                    action: 'apfreepass_passkey_get_registration_challenge',
                    nonce: nonce,
                    username: username,
                    email: email,
                    device_name: deviceName,
                },
                success: function(response) {
                    if (!response.success) {
                        showMessage('#apfreepass-passkey-register-message',
                            response.data?.message || i18n.error || 'An error occurred.', 'error');
                        setLoading($btn, false);
                        return;
                    }

                    var challenge = base64urlToBuffer(response.data.challenge);
                    state.passkeyChallengeId = response.data.challenge_id;
                    var userId = base64urlToBuffer(response.data.user_id);

                    var options = {
                        publicKey: {
                            rp: {
                                name: siteName,
                                id: rpId,
                            },
                            user: {
                                id: userId,
                                name: username,
                                displayName: username,
                            },
                            challenge: challenge,
                            pubKeyCredParams: [
                                { alg: -7, type: 'public-key' },  // ES256
                                { alg: -257, type: 'public-key' }, // RS256
                            ],
                            authenticatorSelection: {
                                userVerification: 'required',
                                residentKey: 'preferred',
                            },
                            timeout: 60000,
                            attestation: 'none',
                        }
                    };

                    navigator.credentials.create(options)
                        .then(function(credential) {
                            return registerPasskeyCredential(credential, username, email, deviceName);
                        })
                        .catch(function(err) {
                            if (err.name === 'NotAllowedError') {
                                showMessage('#apfreepass-passkey-register-message',
                                    i18n.passkeyCancelled || 'Registration was cancelled.', 'error');
                            } else if (err.name === 'InvalidStateError') {
                                showMessage('#apfreepass-passkey-register-message',
                                    'A passkey already exists for this device.', 'error');
                            } else {
                                showMessage('#apfreepass-passkey-register-message',
                                    i18n.passkeyError || 'Passkey registration failed. Please try again.', 'error');
                            }
                            setLoading($btn, false);
                        });
                },
                error: function() {
                    showMessage('#apfreepass-passkey-register-message',
                        i18n.error || 'An error occurred. Please try again.', 'error');
                    setLoading($btn, false);
                }
            });
        });
    }

    function bindPasskeyRevocation() {
        $('.apfreepass-passkey-revoke').on('click', function() {
            var $button = $(this);
            if (!window.confirm('Remove this passkey from your account?')) return;
            $button.prop('disabled', true);
            $.ajax({
                url: ajaxurl, method: 'POST',
                data: {action: 'apfreepass_passkey_revoke', nonce: nonce, credential_row_id: $button.data('credential-id')},
                success: function(response) {
                    if (response.success) {
                        $button.closest('li').remove();
                        showMessage('#apfreepass-passkey-revoke-message', response.data?.message || 'Passkey removed.', 'success');
                    } else {
                        showMessage('#apfreepass-passkey-revoke-message', response.data?.message || 'Could not remove passkey.', 'error');
                        $button.prop('disabled', false);
                    }
                },
                error: function(xhr) {
                    var message = xhr.responseJSON?.data?.message || 'Could not remove passkey.';
                    showMessage('#apfreepass-passkey-revoke-message', message, 'error');
                    $button.prop('disabled', false);
                }
            });
        });
    }

    function bindPasskeyModeToggle() {
        $('#apfreepass-toggle-passkey-mode').on('click', function() {
            var $auth = $('#apfreepass-passkey-auth');
            var $register = $('#apfreepass-passkey-register');
            var $text = $('#apfreepass-passkey-mode-text');

            if (state.passkeyMode === 'login') {
                state.passkeyMode = 'register';
                $auth.hide();
                $register.show();
                $text.text(i18n.switchToLogin || 'Sign in with existing passkey');
            } else {
                state.passkeyMode = 'login';
                $auth.show();
                $register.hide();
                $text.text(i18n.switchToRegister || 'Create a new passkey instead');
            }
        });
    }

    function initPasskeySupport() {
        if (!window.PublicKeyCredential) {
            // Passkeys not supported - could hide the tab or show a notice
            console.log('WebAuthn not supported');
        }
    }

    function verifyPasskeyAssertion(credential) {
        var authData = credential.response.authenticatorData;
        var clientDataJSON = credential.response.clientDataJSON;
        var signature = credential.response.signature;
        var userHandle = credential.response.userHandle;

        $.ajax({
            url: ajaxurl,
            method: 'POST',
            data: {
                action: 'apfreepass_passkey_verify_assertion',
                nonce: nonce,
                credential_id: bufferToBase64url(credential.rawId),
                authenticator_data: bufferToBase64url(authData),
                client_data_json: bufferToBase64url(clientDataJSON),
                signature: bufferToBase64url(signature),
                user_handle: userHandle ? bufferToBase64url(userHandle) : null,
                challenge_id: state.passkeyChallengeId,
                redirect: redirect,
            },
            success: function(response) {
                if (response.success) {
                    showMessage('#apfreepass-passkey-login-message',
                        i18n.passkeyAuthenticated || 'Authenticated! Redirecting...', 'success');
                    setTimeout(function() {
                        window.location.href = response.data?.redirect || redirect || apfreepassAuth.redirect || '/';
                    }, 1000);
                } else {
                    showMessage('#apfreepass-passkey-login-message',
                        response.data?.message || i18n.passkeyError || 'Authentication failed.', 'error');
                }
            },
            error: function() {
                showMessage('#apfreepass-passkey-login-message',
                    i18n.error || 'An error occurred. Please try again.', 'error');
            }
        });
    }

    function registerPasskeyCredential(credential, username, email, deviceName) {
        var attestationObject = credential.response.attestationObject;
        var clientDataJSON = credential.response.clientDataJSON;
        var transports = credential.response.getTransports ? credential.response.getTransports() : [];

        $.ajax({
            url: ajaxurl,
            method: 'POST',
            data: {
                action: 'apfreepass_passkey_register_credential',
                nonce: nonce,
                credential_id: bufferToBase64url(credential.rawId),
                attestation_object: bufferToBase64url(attestationObject),
                client_data_json: bufferToBase64url(clientDataJSON),
                transports: JSON.stringify(transports),
                device_name: deviceName,
                challenge_id: state.passkeyChallengeId,
            },
            success: function(response) {
                if (response.success) {
                    showMessage('#apfreepass-passkey-register-message',
                        i18n.passkeyCreated || 'Passkey created! Redirecting...', 'success');
                    setTimeout(function() {
                        window.location.href = response.data?.redirect || redirect || apfreepassAuth.redirect || '/';
                    }, 1000);
                } else {
                    showMessage('#apfreepass-passkey-register-message',
                        response.data?.message || i18n.passkeyError || 'Registration failed.', 'error');
                }
            },
            error: function() {
                showMessage('#apfreepass-passkey-register-message',
                    i18n.error || 'An error occurred. Please try again.', 'error');
            }
        });
    }

    // Utility functions
    function showMessage(selector, message, type) {
        var $el = $(selector);
        $el.removeClass('success error info').addClass(type).text(message).show();
    }

    function clearMessage(selector) {
        $(selector).hide().removeClass('success error info').empty();
    }

    function clearAllMessages() {
        $container.find('.auth-message').hide().removeClass('success error info').empty();
    }

    function setLoading($btn, loading) {
        if (loading) {
            $btn.addClass('loading').prop('disabled', true);
            $btn.find('.btn-text').hide();
            $btn.find('.btn-loading').show();
        } else {
            $btn.removeClass('loading').prop('disabled', false);
            $btn.find('.btn-text').show();
            $btn.find('.btn-loading').hide();
        }
    }

    function isValidEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }

    function base64urlToBuffer(base64url) {
        var base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        var padding = base64.length % 4;
        if (padding) base64 += '='.repeat(4 - padding);
        var binary = atob(base64);
        var buffer = new ArrayBuffer(binary.length);
        var view = new Uint8Array(buffer);
        for (var i = 0; i < binary.length; i++) {
            view[i] = binary.charCodeAt(i);
        }
        return buffer;
    }

    function bufferToBase64url(buffer) {
        var bytes = new Uint8Array(buffer);
        var binary = '';
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        var base64 = btoa(binary);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    // Initialize on document ready
    $(document).ready(init);

    // Expose for testing
    window.apfreepassAuthJS = {
        init: init,
        bufferToBase64url: bufferToBase64url,
        base64urlToBuffer: base64urlToBuffer,
    };

})(jQuery);
