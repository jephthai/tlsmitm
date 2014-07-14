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
var fs  = require("fs");
try {
    var moment = require("moment");
} catch(e) {
    out.red("ERROR loading `moment` library");
    out.red("Try installing it with 'npm install moment'");
    process.exit(2);
}

var printreadable = function(data, padding) {
    var str = "";
    var i, j;
    for(i = 0; i < data.length; i++) {
	var character = data.readUInt8(i);
	if(character > 0x20 && character < 0x7f) {
	    str += String.fromCharCode(character);
	} else if(character == 0x0a) {
	    str += "\n";
            for(j = 0; j < padding; j++) {
		str += " ";
	    }
	} else if(character == 0x20) {
	    str += " ";
	} else if(character == 0x0d) {
	    // we skip LFs
	} else {
	    str += ".";
	}
    }
    return str.replace(/^\s*$/gm, "").replace(/\n+/, "\n").trim();
}

module.exports.filer = function(relay, direction, data) { 
    out.cyan("Filer output logger not implemented yet");
}

module.exports.screen = function(relay, direction, data) {
    var clientid = "[" + relay.id + "] ";
    var printer = direction == "client" ? out.green : out.blue;
    printer(clientid + printreadable(data, clientid.length + 9));
}

module.exports.filer = function(filename) {
    var outclient = fs.openSync(filename, "w");
    
    this.send = function(relay, direction, data) {
	//
	// a header needs the following fields:
	//
	// timestamp   -- UNIX timestamp as 32-bit integer
	// relay ID    -- 32-bit integer
	// direction   -- 8-bit integer (0 = client, 1 = server)
	// client IP   -- 32-bit integer (IP address)
	// client port -- 16-bit integer
	// server IP   -- 32-bit integer (IP address)
	// server port -- 16-bit integer
	// bytes       -- 32-bit integer denoting message length
	//
	var header     = new Buffer(29);
	var clientip   = new Buffer(relay.clientip.split(/\./).map(function(x) { parseInt(x) }));
	var clientport = relay.clientport;
	var serverip   = new Buffer(relay.serverip.split(/\./).map(function(x) { parseInt(x) }));
	var serverport = relay.serverport;
	
	header.write("MESG"                               , 0);
	header.writeUInt32LE((new moment()).unix()        , 4);
	header.writeUInt32LE(relay.id                     , 8);
	header.writeUInt8(direction == "client" ? 0 : 1   , 12);
	header.copy(clientip, 0, 13, 16);
	header.writeUInt16LE(clientport                   , 17);
	header.copy(serverip, 0, 19, 22);
	header.writeUInt16LE(serverport                   , 23);
	header.writeUInt32LE(data.length                  , 25);

	fs.writeSync(outclient, header, 0, header.length, null);
	fs.writeSync(outclient, data, 0, data.length, null);
    }
}
