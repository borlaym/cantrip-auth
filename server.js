var cantrip = require("Cantrip");
var auth = require("./index.js");

cantrip.use(auth);

cantrip.start();
