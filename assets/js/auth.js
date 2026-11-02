(function ($) {
    'use strict';
    $(function () {
        $('#apfreepass-magic-link-form').on('submit', function (event) {
            event.preventDefault();
            var form = $(this), button = form.find('button[type="submit"]');
            var message = form.find('#apfreepass-magic-link-message');
            button.prop('disabled', true); message.text('');
            $.ajax({url: window.apfreepassAuth.ajaxurl, method: 'POST', data: form.serialize(), dataType: 'json'})
                .done(function (response) {
                    message.text(response && response.success ? 'If an account exists, a sign-in link has been sent.' : (response && response.data && response.data.message ? response.data.message : 'Unable to send the link. Please try again.'));
                }).fail(function () { message.text('Unable to send the link. Please try again.'); })
                .always(function () { button.prop('disabled', false); });
        });
    });
})(jQuery);
