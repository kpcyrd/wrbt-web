'use strict';

var WRBT_VERSION = 1;
var PREFIX = 'http://wrbt.hyperboria.net/';

document.addEventListener('DOMContentLoaded', function() {
    var body = document.getElementsByTagName('body')[0];

    var key2b64 = function(x) {
        return btoa(String.fromCharCode.apply(null, x));
    };

    var b642key = function(x) {
        return new Uint8Array(atob(x).split("").map(function(c) {
                return c.charCodeAt(0); }));
    };

    var qs = function(url) {
        return queryString.parse(url.substr(url.indexOf('#') + 1));
    };

    document.getElementById('start').onclick = function() {
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

    document.getElementById('gen-request').onclick = function() {
        var nacl = nacl_factory.instantiate();
        var keypair = nacl.crypto_box_keypair();
        var query = {
            type: 'peer',
            interface: 'udp',
            pk: key2b64(keypair.boxPk),
            wrbtVersion: WRBT_VERSION
        };

        document.getElementById('sk').value = key2b64(keypair.boxSk);
        document.getElementById('request-output').value = PREFIX + '#' + queryString.stringify(query);
    };

    document.getElementById('gen-offer').onclick = function() {
        var nacl = nacl_factory.instantiate();

        var keypair = nacl.crypto_box_keypair();
        var nonce = nacl.crypto_box_random_nonce();

        var url = document.getElementById('request-input').value;
        var request = qs(url);
        var pk = b642key(request.pk);

        var addr = document.getElementById('addr').value;
        var cjdnspk = document.getElementById('pk').value;
        var password = document.getElementById('password').value;

        var offer = {credentials: {}};
        offer.credentials[addr] = {
            'publicKey': cjdnspk,
            'password': password
        };

        offer = JSON.stringify(offer);

        var packet = nacl.crypto_box(nacl.encode_utf8(offer), nonce, pk, keypair.boxSk);

        var response = {
            type: 'credentials',
            interface: 'udp',
            message: key2b64(packet),
            pk: key2b64(keypair.boxPk),
            n: key2b64(nonce),
            wrbtVersion: WRBT_VERSION
        };

        var query = queryString.stringify(response);
        document.getElementById('offer-output').value = PREFIX + '#' + query;
    };

    document.getElementById('decrypt').onclick = function() {
        var nacl = nacl_factory.instantiate();

        var offer = qs(document.getElementById('offer-input').value);
        var priv = b642key(document.getElementById('sk').value);

        var sender = b642key(offer.pk);

        var msg = nacl.crypto_box_open(b642key(offer.message), b642key(offer.n), sender, priv);
        msg = nacl.decode_utf8(msg);

        document.getElementById('response-output').value = msg;
    };
});
