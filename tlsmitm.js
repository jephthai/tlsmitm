//
// TLS MITM - an SSL relay for analyzing network communications
// Copyright (C) 2014 Josh Stone
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
//

var fs = require('fs');
var tls = require('tls');
var out = require ("./out.js");
var relay = require("./relay.js");
var loggers = require("./loggers.js");
 
// 
// This is a certificate that lasts for 10 years after 2014-07-11 for
// the FQDN of www.example.com.  So, in other words, this should be
// an invalid cert for just about anything -- you can replace it with
// another cert if you like.
//

var options = {
    key: "-----BEGIN RSA PRIVATE KEY-----\n"+
	"MIIEowIBAAKCAQEAu6+3vSWAU6S1LlaQZe1tipdz/YZHMU3PQh/z4qCy18SAMGZs\n"+
	"KjzZ80wip+qjXpEpOz4RuTCRAvcutStFocj7lMY1dSlhk5GcsyXPcm9UEGjhxtL0\n"+
	"HzbU3r5K3/9jUaIX14z1mFUz/MpZRDW34zIJ54Pu8AAdUnJTvuGcFbuimrp3Fux9\n"+
	"kNsu9txsoGDFEYD/QTqAaQL06I3iFtGU+F/yz+8AjgHdC97TrY5+NRmEGFg5nX5s\n"+
	"at64sfhn5k4h7COzTRYqt9COUTfi8VX/raQ/VyXY4zkbzkvUa6/+WmfCF78qYofr\n"+
	"8jjrqALGDvmo+NX2NG61eCioZE23UuRBntZSVwIDAQABAoIBAFDatTP12N+vwCHT\n"+
	"RueyLhObhWt9kmPqGlRpQX6rLgCH9ZVkOkrD5jzK2s8t5O1TacjMx4PZKU92vxdr\n"+
	"Kdc1pzQDY3oytoeFHlWK/2BUF4nuNP2bWXGtBG1k2wq+kcHUK6M/ZXoXkorffS9G\n"+
	"WQ62OtAS5TddRUSEXhGITd6K89TlrJScyo7T5IhfijmAoNg+fUlj4Rs3OGSWsZTz\n"+
	"p4fSNNYP1Ern8Up2kKyEeAxmxq4AHoPdt2igChP7+MIZravyHqA6cjBTnbKPDseG\n"+
	"o2K8jSP0hulG9mZNuVEY8/Tu/pFspBs6fRgsev1oIIK9bgNrHFVGJT+cwxRwyG6s\n"+
	"vcVJEuECgYEA3JgASXcZVSFokg0/dnhcwL3Dfb7kWg8TFk6i104D8LwnaM4AZqzw\n"+
	"QUpJ1/VXMo+pLXM8IoimgDKfcD3XA6wJtCouNIMjJYUwaiw/MwKqHdBgz1rJz+p3\n"+
	"NGzUCQbHiHNgIjEuIKKv3Pmjt+HazfnZjD5z3mRzklTVG7vIxHMCPicCgYEA2c+V\n"+
	"Ojl9MsYHOt7DPRcYBoz0+rYoeUii3QNj/UcuuoYhuDRkjJdjCpf1IdkXJwKD5m+M\n"+
	"yK3cQLG1GofYjKrmOcNVw6OQfkII2yMIWx0HBqMScmY02dQkkRAqm8TZ2mBKj+M9\n"+
	"HsCCkEhVstUakZ1ra1g9LCrty+fGeIEbuH1rGFECgYBSWCtDQUIjlSUD4A4gmy2E\n"+
	"hVHETs3PEHF/kjsXQ/gUlSfg54Uezs+gj6qhAuRZ62aroKiB+6CrmjoKHAt3Q3Eb\n"+
	"3+L/lzQ3fVBlUb8Fu6jlGDQLM0jCZDO7TiSYef9h4C+yk8k0RYaAZm/G5HhZCzs6\n"+
	"LtXx3m2F4kTq5V48dvIPYQKBgFYeNSpoQJAqrAEiwp8M2nr8kH/wNeB+T6aDCK3D\n"+
	"zz4AeqSSUo8j7AzsOAfCBd1uqSgbQta1pzgNC0YKIBy+FXkROn+31BGXmljKaStd\n"+
	"NsHxCAIjVxIpRqv0cGRWWKx3FgP+HNRj2Tui3f9vMqoQS8CNiuJDtvHAGkDbC1LO\n"+
	"g+GBAoGBAJGega1Wd9Syyle4j0wykUFQsVwMzrjhJ9SiBgZfLFRyE8gwLNRoYwYC\n"+
	"hvOI0mngZ/eQx2RHp1Puu/fz9ZtMOGgeLILNXSrwi+h1yVOJzoJLY88tf9FnvDSI\n"+
	"m3xPWsYhYRL4QKavayVGt8LCeFh/P/brJqPszGzFaab2zgbAyjMc\n"+
	"-----END RSA PRIVATE KEY-----",
    cert: "-----BEGIN CERTIFICATE-----\n"+
	"MIIDOjCCAiICCQCeInYV1/bl9zANBgkqhkiG9w0BAQUFADBfMQswCQYDVQQGEwJB\n"+
	"VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0\n"+
	"cyBQdHkgTHRkMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wHhcNMTQwNzExMTUz\n"+
	"MDAzWhcNMjQwNzA4MTUzMDAzWjBfMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29t\n"+
	"ZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRgwFgYD\n"+
	"VQQDDA93d3cuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"+
	"AoIBAQC7r7e9JYBTpLUuVpBl7W2Kl3P9hkcxTc9CH/PioLLXxIAwZmwqPNnzTCKn\n"+
	"6qNekSk7PhG5MJEC9y61K0WhyPuUxjV1KWGTkZyzJc9yb1QQaOHG0vQfNtTevkrf\n"+
	"/2NRohfXjPWYVTP8yllENbfjMgnng+7wAB1SclO+4ZwVu6KauncW7H2Q2y723Gyg\n"+
	"YMURgP9BOoBpAvTojeIW0ZT4X/LP7wCOAd0L3tOtjn41GYQYWDmdfmxq3rix+Gfm\n"+
	"TiHsI7NNFiq30I5RN+LxVf+tpD9XJdjjORvOS9Rrr/5aZ8IXvypih+vyOOuoAsYO\n"+
	"+aj41fY0brV4KKhkTbdS5EGe1lJXAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAFnr\n"+
	"unfExfdVmTtoEY5c/qbnFZXujcbaK27MnFXZ/vdhQnCYVOJgEjXLbRIwYgHQXgZz\n"+
	"6Y2tmf1g0VwNDGVuor+lEiSUM/0QrnMdRvFja59Kc2Kr1PIQ+xwo6C0IFhyjArh6\n"+
	"Gv6zPaPHhDgG3qq7lRBl0ZX50iqDRPeNU+WujGijT9B/G9SVCwrdqXwVQXoOP7d+\n"+
	"LzVc1Ws1FIDUb1T3oqjF+gJNXgBPZK8yB6ta2LsqhGtnH6Pu5ec7E2KDe6Rp7Mtd\n"+
	"CiG8RME2UaJxV24cxfu50yevsLaTyQ6no9o+pPV2XrfDGqKtHMOBYR+vKoU/mtBS\n"+
	"dUjDQZMjn0l6MWBAaqg=\n"+
	"-----END CERTIFICATE-----"
};

out.green("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-");
out.cyan ("     Josh's TLS MitM Proxy - yakovdk@gmail.com - (C) 2014");
out.green("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-");

if(process.argv.length != 5) {
    console.log("\n usage: tlsmitm.js <lport> <rhost> <rport>\n");
    process.exit(1);
}

var lport = process.argv[2];
var rhost = process.argv[3];
var rport = process.argv[4];

out.red("Writing client comms to 'outclient.dat'");
out.red("Writing server comms to 'outserver.dat'");

var filer   = new loggers.filer("output.dat");
var loglist = [filer.send, loggers.screen];
var logger = new Object();

logger.send = function(relay, direction, data) {
    loglist.map(function(l) {
	l(relay, direction, data);
    });
}       

relay.init(rhost, rport, logger);
var server = tls.createServer(options, relay.relay);

server.listen(lport, function() {
    out.red('server bound to 0.0.0.0:'+lport);
});
