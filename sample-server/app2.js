var express = require('express');
var https = require('https');
var http = require('http');
var fs = require('fs');

// This line is from the Node.js HTTPS documentation.
var options = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.pem')
};

// Create a service (the alspp object is just a callback).
var app = express();


const port = 443

app.get('/', (req, res) => {
  res.send('Hello World from app 1!')
})

// Create an HTTP service.
//http.createServer(app).listen(port);
// Create an HTTPS service identical to the HTTP service.
https.createServer(options, app).listen(port);