var request = require("request");
var Cantrip = require("Cantrip");
var auth = require("../index.js");

describe("The access-control middleware for Cantrip", function() {

	Cantrip.options.port = 3001;
	var serverUrl = "http://localhost:3001/";

	it("should initialize", function() {
		expect(Cantrip).toBeDefined();
	});

	Cantrip.options.file = "tests/test" + Math.floor(Math.random() * 10000000000) + ".json";

	Cantrip.use(auth);

	Cantrip.start();
	Cantrip.data = {
		"_contents": {
			"foo": "bar",
			"child": {
				"secret": "secret"
			}
		},
		"_salt": "cantrip-auth-test-salt",
		"_acl": {
			"/": {
			},
			"/child": {
				"GET": ["super"]
			}
		},
		"_users": [{
			"_id": "super",
			"password": "363bbc1b6745434341bc15eb4358dc18", //password is asdasd
			"roles": ["super"]
		}]
	};

	var token;


	describe("Denying access to unauthorized requests", function() {

		it("should allow you to access the unrestricted root object", function(done) {
			request({
				method: "GET",
				url: serverUrl,
				json: true
			}, function(error, response, body) {
				expect(body.foo).toBe("bar");
				expect(body.child.secret).toBe("secret");
				done();
			});
		});

		it("should throw an error when trying to access a restricted object", function(done) {
			request({
				method: "GET",
				url: serverUrl + "child",
				json: true
			}, function(error, response, body) {
				expect(body.error).toBeDefined();
				done();
			});
		});
		it("should throw an error when trying to access a meta object", function(done) {
			request({
				method: "GET",
				url: serverUrl + "_salt",
				json: true
			}, function(error, response, body) {
				expect(body.error).toBeDefined();
				done();
			});
		});

	});

	describe("User management", function() {

		it("should allow you to register a new user with a given _id and password", function(done) {
			request({
				method: "POST",
				url: serverUrl + "signup",
				json: {
					"_id": "testUser1",
					"password": "asdasd"
				}
			}, function(error, response, body) {
				expect(body._id).toBe("testUser1");
				expect(body.password).not.toBeDefined(); //Omits the created password hash
				expect(body.roles.length).toBe(0); //Omits the created password hash
				expect(Cantrip.data._users[1].password).toBeDefined(); //But we store it
				expect(Cantrip.data._users[1].password.length).toBe(32); //As a hash
				done();
			});
		});

		it("should overwrite the roles array if you specified it", function(done) {
			request({
				method: "POST",
				url: serverUrl + "signup",
				json: {
					"password": "asdasd",
					"roles": ["super", "admin"]
				}
			}, function(error, response, body) {
				expect(body._id).toBeDefined();
				expect(body.roles.length).toBe(0);
				done();
			});
		});

		it("should throw an error if you didn't specify a password (but you don't need an id)", function(done) {
			request({
				method: "POST",
				url: serverUrl + "signup",
				json: {}
			}, function(error, response, body) {
				expect(body.error).toBeDefined();
				done();
			});
		});

		it("shouldn't let you register with an _id that already exists", function(done) {
			request({
				method: "POST",
				url: serverUrl + "signup",
				json: {
					"_id": "super",
					"password": "asdasd"
				}
			}, function(error, response, body) {
				expect(body.error).toBeDefined();
				done();
			});
		});

		it("shouldlet throw an error if you try to log in using the wrong password", function(done) {
			request({
				method: "POST",
				url: serverUrl + "login",
				json: {
					"_id": "super",
					"password": "wrong"
				}
			}, function(error, response, body) {
				expect(body.error).toBeDefined();
				done();
			});
		});

		it("should let you log in, returning a token", function(done) {
			request({
				method: "POST",
				url: serverUrl + "login",
				json: {
					"_id": "super",
					"password": "asdasd"
				}
			}, function(error, response, body) {
				expect(body.token).toBeDefined();
				expect(body.expires).toBeDefined();
				token = body.token;
				done();
			});
		});

		it("should let you access content only available to your roles by using the accessToken GET parameter and your new token", function(done) {
			request({
				method: "GET",
				url: serverUrl + "child?accessToken=" + token,
				json: {}
			}, function(error, response, body) {
				expect(body.secret).toBe("secret");
				done();
			});
		});

		it("should also work with Authorization header", function(done) {
			request({
				method: "GET",
				url: serverUrl + "child",
				headers: {
					"Authorization": "Token " + token
				},
				json: {}
			}, function(error, response, body) {
				expect(body.secret).toBe("secret");
				done();
			});
		});

		it("should allow access to _meta objects as super user", function(done) {
			request({
				method: "GET",
				url: serverUrl + "_salt",
				headers: {
					"Authorization": "Token " + token
				},
				json: {}
			}, function(error, response, body) {
				expect(body.value).toBe("cantrip-auth-test-salt");
				done();
			});
		});

		it("when you log in as a non-super user", function(done) {
			request({
				method: "POST",
				url: serverUrl + "login",
				json: {"_id": "testUser1", "password": "asdasd"}
			}, function(error, response, body) {
				expect(body.token).toBeDefined();
				token = body.token;
				done();
			});
		});

		it("still shouldn't let you get a restricted object", function(done) {
			request({
				method: "GET",
				url: serverUrl + "child",
				headers: {
					"Authorization": "Token " + token
				},
				json: {}
			}, function(error, response, body) {
				expect(body.error).toBeDefined();
				done();
			});
		});

		it("or a meta object", function(done) {
			request({
				method: "GET",
				url: serverUrl + "_acl",
				headers: {
					"Authorization": "Token " + token
				},
				json: {}
			}, function(error, response, body) {
				expect(body.error).toBeDefined();
				done();
			});
		});

	});
});