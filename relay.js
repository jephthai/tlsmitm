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

var out = require("./out.js");
var tls = require("tls");

var nextid   = 0;
var desthost = "";
var destport = 0;
var logger   = null;
var tlsopts  = { rejectUnauthorized: false };

function settleRelay(relay) {
    if(relay.ready == 2) {
	relay.clientsock.resume();
	relay.serversock.resume();
    } else {
	setTimeout(settleRelay, 100, relay);
    }
}

module.exports.init = function(host, port, logs) {
    desthost = host;
    destport = port;
    logger   = logs;
};

module.exports.relay = function(clientsock) {
    var myself = this;
    clientsock.pause();
    this.clientsock = clientsock;
    this.id = nextid++;
    this.clientip = this.clientsock.remoteAddress;
    this.clientport = this.clientsock.remotePort;
    this.ready = 0;
    out.red("["+this.id+"] Client connected from " + this.clientsock.remoteAddress);

    this.serversock = tls.connect(destport, desthost, tlsopts, function() { 
	out.red("Setting serverip to " + myself.serversock.remoteAddress);
	myself.serverip = myself.serversock.remoteAddress;
	myself.serverport = myself.serversock.remotePort;
	myself.ready += 1;
    });
    this.serversock.pause();
    this.serversock.on('data', function(data) {
	myself.clientsock.write(data);
	logger.send(myself, "server", data);
    });
    this.serversock.on('end', function() {
	out.red("["+myself.id+"] Server socket ended");
	if(myself.clientsock) 
	    myself.clientsock.destroy();
    });
    this.serversock.on('error', function() {});

    this.clientsock.on('data', function(data) {
	myself.serversock.write(data);
	logger.send(myself, "client", data);
    });
    this.clientsock.on('end', function() {
	out.red("["+myself.id+"] Client socket ended");
	if(myself.serversock) 
	    myself.serversock.destroy();
    });
    this.clientsock.on('error', function() {});
    
    setTimeout(settleRelay, 100, myself);
    this.ready += 1;
}

