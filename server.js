var cantrip = require("Cantrip");
var auth = require("./index.js");

auth.options.emailServer = {
	host: "smtp.sendgrid.net", // hostname
    secureConnection: false, // use SSL
    port: 587, // port for secure SMTP
    auth: {
        user: "kriekmedia",
        pass: "Qvbm97UR"
    }
}

cantrip.use(auth);

cantrip.start();
