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
//
// This program "renders" the contents of the binary file output from
// the loggers.js "filer" object.  This lets the user process the
// results in several different ways that should make exploring what
// went through the relay easier.
//

var fs = require("fs");
var moment = require("moment");
var out = require("./out.js");

out.timestamp = false;

function message(stream) {
    this.header = new Buffer(29);
    fs.readSync(stream, this.header, 0, 29, null);
    this.label = this.header.slice(0,4).toString();
    if(this.label != "MESG" ) {
	// console.log(this.label);
	throw "Not a valid MESG block";
    }
    this.timestamp  = this.header.readUInt32LE(4);
    this.relay      = this.header.readUInt32LE(8);
    this.direction  = this.header.readUInt8(12);
    this.clientip   = this.header.readUInt32LE(13);
    this.clientport = this.header.readUInt16LE(17);
    this.serverip   = this.header.readUInt32LE(19);
    this.serverport = this.header.readUInt16LE(23);
    this.length     = this.header.readUInt32LE(25);

    this.payload   = new Buffer(this.length);
    fs.readSync(stream, this.payload, 0, this.length, null);
}

function groupSessions(ms) {
    var sessions = {};
    ms.map(function(m) {
	if(!sessions[m.relay]) {
	    sessions[m.relay] = []; 
	}
	sessions[m.relay].push(m);
    });
    return sessions;
}
    
function readMessages(filename) {
    var file = fs.openSync(filename, "r");
    var msgs = [];
    
    try {
	while(true) {
	    var msg = new message(file);
	    msgs.push(msg);
	}
    } catch(e) {
    }
    return msgs;
}

function usage() {
    console.log("");
    console.log("  usage: renderjs <filename> <cmd> [args]");
    console.log("");
    console.log("    stats            Show summary stats for input file");
    console.log("    session S        Show list of messages in session S");
    console.log("    message S M      Show message M in session S as UTF-8");
    console.log("    conversation S   Show both sides as UTF-8 from session S");
    console.log("");
}

if(process.argv.length < 4) {
    usage();
    process.exit(1);
}

var msgs = readMessages(process.argv[2]);
var sessions = groupSessions(msgs);

switch(process.argv[3]) {
case "stats":
    console.log("Read " + msgs.length + " sessions");
    for(var session in sessions) {
	console.log("Session " + session + ", with " + sessions[session].length + " messages");
    }
    break;
case "session":
    var sess = sessions[parseInt(process.argv[4])];
    console.log("Session " + process.argv[4] + " with " + sess.length + " messages");
    for(var index in sess) {
	var msg = sess[index];
	var sdr = msg.direction == 0 ? "client" : "server";
	console.log("Message " + index + " from " + sdr + " with " + msg.length + " bytes");
    }
    break;
case "message":
    var sess = sessions[parseInt(process.argv[4])];
    var msg  = sess[parseInt(process.argv[5])];
    console.log(msg.payload.toString("UTF-8"));
    break;
case "conversation":
    var session = sessions[parseInt(process.argv[4])];
    for(var index in session) {
	var msg = session[index];
	var str = msg.payload.toString("UTF-8");
	var fun = msg.direction == 0 ? out.cyan : out.green;
	str.split(/\r*\n/).map(fun);
    }
    break;
default:
    console.log("Unrecognized command");
    usage();
}