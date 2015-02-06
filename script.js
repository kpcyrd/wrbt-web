'use strict';

// STOP TOUCHING //
var WRBT_VERSION = 1;
// START TOUCHING //

var PREFIX = 'http://wrbt.hyperboria.net/';

document.addEventListener('DOMContentLoaded', function() {
    var body = document.getElementsByTagName('body')[0];

    // STOP TOUCHING //
    var key2b64 = function(x) {
        return btoa(String.fromCharCode.apply(null, x));
    };

    var b642key = function(x) {
        return new Uint8Array(atob(x).split("").map(function(c) {
                return c.charCodeAt(0); }));
    };
    // START TOUCHING //

    var qs = function(url) {
        return queryString.parse(url.substr(url.indexOf('#') + 1));
    };

    var $ = function(id) {
        return document.getElementById(id);
    };

    var args = qs(window.location.href);

    if(args['type'] == 'peer') {
        $('splash').hidden = true;
        $('req').hidden = true;
        $('auth').hidden = false;
    } else if(args['type'] == 'secret') {
        $('splash').hidden = true;
        $('decrypt').hidden = false;
        $('req-req-div').hidden = false;
    } else if(args['type'] == 'credentials') {
        $('splash').hidden = true;
        $('req').hidden = true;
        $('decrypt-info').hidden = false;
    }

    $('start').onclick = function() {
        var i = 0;
        var step = 75;
        var interval = 10;
        var splash = document.getElementById('splash');
        var rawHeight = getComputedStyle(splash, null).getPropertyValue('height');
        var height = parseInt(rawHeight.substr(0, rawHeight.length - 2));
        var tick = function() {
            splash.style.top = '-' + i + 'px';
            if(height > i) {
                i += step;
                setTimeout(tick, interval);
            }
        };
        setTimeout(tick, interval);
    };

    $('req-do').onclick = function() {
        // STOP TOUCHING //
        var nacl = nacl_factory.instantiate();
        var keypair = nacl.crypto_box_keypair();
        var query = {
            type: 'peer',
            interface: 'udp',
            pk: key2b64(keypair.boxPk),
            wrbtVersion: WRBT_VERSION
        };
        var my_private = key2b64(keypair.boxSk);
        // START TOUCHING //

        $('req-req').value = PREFIX + '#' + queryString.stringify(query);
        $('decrypt').hidden = false;
        $('req-req-div').hidden = false;
        window.location.hash = '#' + queryString.stringify({
            type: 'secret',
            sk: my_private
        });
    };

    $('auth-do').onclick = function() {
        var request = window.location.href;
        var name = $('auth-name').value;
        var server = $('auth-server').value;
        var pw = $('auth-pw').value;

        // STOP TOUCHING //
        var auth = Crypto.HMAC(Crypto.SHA256, request, pw);

        var query = queryString.stringify({
            method: 'authorize',
            auth: auth,
            payload: request,
            name: name
        });
        // START TOUCHING //

        var xhr = new XMLHttpRequest();
        xhr.onload = function() {
            var resp = JSON.parse(xhr.responseText);
            if('error' in resp) {
                $('auth-offer').value = 'Error: ' + resp['error'];
            } else {
                $('auth-offer').value = resp['response'];
            }
        };
        xhr.open('POST', server, true);
        xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
        xhr.send(query);
    };

    $('gen-offer').onclick = function() {
        var url = window.location.href;
        var addr = document.getElementById('addr').value;
        var cjdnspk = document.getElementById('pk').value;
        var password = document.getElementById('password').value;

        var request = qs(url);

        // STOP TOUCHING //
        var his_public = b642key(request.pk);

        var nacl = nacl_factory.instantiate();

        var my_keypair = nacl.crypto_box_keypair();
        var nonce = nacl.crypto_box_random_nonce();

        var offer = {credentials: {}};
        offer.credentials[addr] = {
            'publicKey': cjdnspk,
            'password': password
        };

        offer = JSON.stringify(offer);

        var packet = nacl.crypto_box(nacl.encode_utf8(offer), nonce, his_public, my_keypair.boxSk);

        var response = {
            type: 'credentials',
            interface: 'udp',
            message: key2b64(packet),
            pk: key2b64(my_keypair.boxPk),
            n: key2b64(nonce),
            wrbtVersion: WRBT_VERSION
        };
        // START TOUCHING //

        var query = queryString.stringify(response);
        document.getElementById('offer-output').value = PREFIX + '#' + query;
    };

    document.getElementById('decrypt').onclick = function() {
        var offer = qs($('offer-input').value);

        // STOP TOUCHING //
        var nacl = nacl_factory.instantiate();

        var my_private = b642key(qs(window.location.href).sk);

        var msg = nacl.crypto_box_open(b642key(offer.message), b642key(offer.n), b642key(offer.pk), my_private);
        msg = nacl.decode_utf8(msg);
        // START TOUCHING //

        document.getElementById('response-output').value = msg;
    };
});
