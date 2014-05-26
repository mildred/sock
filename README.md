sock - node.js module to create sockets and bind them
=====================================================

node.js does not allow to bind outgoing sockets to local port numbers. What's
missing is the localPort option from net.connect. This module is a workaround
that will let you create sockets from a C++ module, and use them in JavaScript.

Usage:

    var net  = require('net');
    var sock = require('sock');
    
    var fd = sock.socket({
      node:     '',           // The local address to bind the socket to.
      service:  '22',         // the local port/service name to bind the socket to.
      socktype: 'SOCK_DGRAM', // Also understands 'SOCK_STREAM'
      family:   'AF_UNSPEC',  // Also understands 'AF_INET' and 'AF_INET6'
      protocol: 0,
      flags:    0
    });
    
    var sock = new Socket({fd: fd});
    sock.connect(1234, 'some_distant_host')
    
    sock.close(fd);

All is synchroneous unfortunately.

The module uses the `getaddrinfo` function that can resolve hostnames and that
may try to open a raw socket unless you specify SOCK_STREAM or SOCK_DGRAM.

