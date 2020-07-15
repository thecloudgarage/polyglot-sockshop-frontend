(function() {
    'use strict';

    var async = require("async"), express = require("express"), request = require("request"), endpoints = require("../endpoints"), helpers = require("../../helpers"),
 app = express(), cookie_name = "logged_in"

var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
const { google } = require('googleapis');
const { AjaxClient } = require('ajax-client');
const OAuth2Data = require('./google_key.json')
const jwt_decode = require('jwt-decode')
const CLIENT_ID = OAuth2Data.web.client_id;
const CLIENT_SECRET = OAuth2Data.web.client_secret;
const REDIRECT_URL = OAuth2Data.web.redirect_uris
const client = new AjaxClient();
const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URL)
var authed = false;

    app.get("/customers/:id", function(req, res, next) {
        helpers.simpleHttpRequest(endpoints.customersUrl + "/" + req.session.customerId, res, next);
    });
    app.get("/cards/:id", function(req, res, next) {
        helpers.simpleHttpRequest(endpoints.cardsUrl + "/" + req.params.id, res, next);
    });

    app.get("/customers", function(req, res, next) {
        helpers.simpleHttpRequest(endpoints.customersUrl, res, next);
    });
    app.get("/addresses", function(req, res, next) {
        helpers.simpleHttpRequest(endpoints.addressUrl, res, next);
    });
    app.get("/cards", function(req, res, next) {
        helpers.simpleHttpRequest(endpoints.cardsUrl, res, next);
    });

    // Create Customer - TO BE USED FOR TESTING ONLY (for now)
    app.post("/customers", function(req, res, next) {
        var options = {
            uri: endpoints.customersUrl,
            method: 'POST',
            json: true,
            body: req.body
        };

        console.log("Posting Customer: " + JSON.stringify(req.body));

        request(options, function(error, response, body) {
            if (error) {
                return next(error);
            }
            helpers.respondSuccessBody(res, JSON.stringify(body));
        }.bind({
            res: res
        }));
    });

    app.post("/addresses", function(req, res, next) {
        req.body.userID = helpers.getCustomerId(req, app.get("env"));

        var options = {
            uri: endpoints.addressUrl,
            method: 'POST',
            json: true,
            body: req.body
        };
        console.log("Posting Address: " + JSON.stringify(req.body));
        request(options, function(error, response, body) {
            if (error) {
                return next(error);
            }
            helpers.respondSuccessBody(res, JSON.stringify(body));
        }.bind({
            res: res
        }));
    });

    app.get("/card", function(req, res, next) {
        var custId = helpers.getCustomerId(req, app.get("env"));
        var options = {
            uri: endpoints.customersUrl + '/' + custId + '/cards',
            method: 'GET',
        };
        request(options, function(error, response, body) {
            if (error) {
                return next(error);
            }
            var data = JSON.parse(body);
            if (data.status_code !== 500 && data._embedded.card.length !== 0 ) {
                var resp = {
                    "number": data._embedded.card[0].longNum.slice(-4)
                };
                return helpers.respondSuccessBody(res, JSON.stringify(resp));
            }
            return helpers.respondSuccessBody(res, JSON.stringify({"status_code": 500}));
        }.bind({
            res: res
        }));
    });

    app.get("/address", function(req, res, next) {
        var custId = helpers.getCustomerId(req, app.get("env"));
        var options = {
            uri: endpoints.customersUrl + '/' + custId + '/addresses',
            method: 'GET',
        };
        request(options, function(error, response, body) {
            if (error) {
                return next(error);
            }
            var data = JSON.parse(body);
            if (data.status_code !== 500 && data._embedded.address.length !== 0 ) {
                var resp = data._embedded.address[0];
                return helpers.respondSuccessBody(res, JSON.stringify(resp));
            }
            return helpers.respondSuccessBody(res, JSON.stringify({"status_code": 500}));
        }.bind({
            res: res
        }));
    });

    app.post("/cards", function(req, res, next) {
        req.body.userID = helpers.getCustomerId(req, app.get("env"));

        var options = {
            uri: endpoints.cardsUrl,
            method: 'POST',
            json: true,
            body: req.body
        };
        console.log("Posting Card: " + JSON.stringify(req.body));
        request(options, function(error, response, body) {
            if (error) {
                return next(error);
            }
            helpers.respondSuccessBody(res, JSON.stringify(body));
        }.bind({
            res: res
        }));
    });

    // Delete Customer - TO BE USED FOR TESTING ONLY (for now)
    app.delete("/customers/:id", function(req, res, next) {
        console.log("Deleting Customer " + req.params.id);
        var options = {
            uri: endpoints.customersUrl + "/" + req.params.id,
            method: 'DELETE'
        };
        request(options, function(error, response, body) {
            if (error) {
                return next(error);
            }
            helpers.respondSuccessBody(res, JSON.stringify(body));
        }.bind({
            res: res
        }));
    });

    // Delete Address - TO BE USED FOR TESTING ONLY (for now)
    app.delete("/addresses/:id", function(req, res, next) {
        console.log("Deleting Address " + req.params.id);
        var options = {
            uri: endpoints.addressUrl + "/" + req.params.id,
            method: 'DELETE'
        };
        request(options, function(error, response, body) {
            if (error) {
                return next(error);
            }
            helpers.respondSuccessBody(res, JSON.stringify(body));
        }.bind({
            res: res
        }));
    });

    // Delete Card - TO BE USED FOR TESTING ONLY (for now)
    app.delete("/cards/:id", function(req, res, next) {
        console.log("Deleting Card " + req.params.id);
        var options = {
            uri: endpoints.cardsUrl + "/" + req.params.id,
            method: 'DELETE'
        };
        request(options, function(error, response, body) {
            if (error) {
                return next(error);
            }
            helpers.respondSuccessBody(res, JSON.stringify(body));
        }.bind({
            res: res
        }));
    });

    app.post("/register", function(req, res, next) {
        var options = {
            uri: endpoints.registerUrl,
            method: 'POST',
            json: true,
            body: req.body
        };
	console.log(req.body)
        console.log("Posting Customer: " + JSON.stringify(req.body));
	console.log(req.body);
        async.waterfall([
                function(callback) {
                    request(options, function(error, response, body) {
                        if (error !== null ) {
                            callback(error);
                            return;
                        }
                        if (response.statusCode == 200 && body != null && body != "") {
                            if (body.error) {
                                callback(body.error);
                                return;
                            }
                            console.log(body);
                            var customerId = body.id;
                            console.log(customerId);
                            req.session.customerId = customerId;
                            callback(null, customerId);
                            return;
                        }
                        console.log(response.statusCode);
                        callback(true);
                    });
                },
                function(custId, callback) {
                    var sessionId = req.session.id;
                    console.log("Merging carts for customer id: " + custId + " and session id: " + sessionId);

                    var options = {
                        uri: endpoints.cartsUrl + "/" + custId + "/merge" + "?sessionId=" + sessionId,
                        method: 'GET'
                    };
                    request(options, function(error, response, body) {
                        if (error) {
                            if(callback) callback(error);
                            return;
                        }
                        console.log('Carts merged.');
                        if(callback) callback(null, custId);
                    });
                }
            ],
            function(err, custId) {
                if (err) {
                    console.log("Error with log in: " + err);
                    res.status(500);
                    res.end();
                    return;
                }
                console.log("set cookie" + custId);
                res.status(200);
                res.cookie(cookie_name, req.session.id, {
                    maxAge: 3600000
                }).send({id: custId});
                console.log("Sent cookies.");
                res.end();
                return;
            }
        );
    });

    app.get("/login", function(req, res, next) {
        console.log("Received login request");

        async.waterfall([
                function(callback) {
                    var options = {
                        headers: {
                            'Authorization': req.get('Authorization')
                        },
                        uri: endpoints.loginUrl
                    };
                    request(options, function(error, response, body) {
                        if (error) {
                            callback(error);
                            return;
                        }
                        if (response.statusCode == 200 && body != null && body != "") {
                            console.log(body);
                            var customerId = JSON.parse(body).user.id;
                            console.log(customerId);
                            req.session.customerId = customerId;
                            callback(null, customerId);
                            return;
                        }
                        console.log(response.statusCode);
                        callback(true);
                    });
                },
                function(custId, callback) {
                    var sessionId = req.session.id;
                    console.log("Merging carts for customer id: " + custId + " and session id: " + sessionId);

                    var options = {
                        uri: endpoints.cartsUrl + "/" + custId + "/merge" + "?sessionId=" + sessionId,
                        method: 'GET'
                    };
                    request(options, function(error, response, body) {
                        if (error) {
                            // if cart fails just log it, it prevenst login
                            console.log(error);
                            //return;
                        }
                        console.log('Carts merged.');
                        callback(null, custId);
                    });
                }
            ],
            function(err, custId) {
                if (err) {
                    console.log("Error with log in: " + err);
                    res.status(401);
                    res.end();
                    return;
                }
                res.status(200);
                res.cookie(cookie_name, req.session.id, {
                    maxAge: 3600000
                }).send('Cookie is set');
                console.log("Sent cookies.");
                res.end();
                return;
            });
    });

app.get('/google-login', (req, res) => {
        if (!authed) {
        // Generate an OAuth URL and redirect there
        const url = oAuth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: 'https://www.googleapis.com/auth/userinfo.email'
        });
        console.log(url)
        res.redirect(url);
    }
});

app.get('/auth/google/callback', function (req, res, next) {
    const code = req.query.code
    if (code) {
        // Get an access token based on our OAuth code
        oAuth2Client.getToken(code, function (err, tokens) {
            if (err) {
                console.log('Error authenticating')
                console.log(err);
            } else {
                console.log('Successfully authenticated');
                oAuth2Client.setCredentials(tokens);
                var token_id = tokens.id_token;
                var decoded = jwt_decode(token_id);
                console.log(decoded.email);
                authed = true;
                var postvals = JSON.stringify({
                        "username": decoded.email,
			"password": decoded.sub,
                        "email": decoded.email,
                        "firstName": decoded.email,
                        "lastName": decoded.email
                 });
				var options = {
					uri: 'http://sock-shop.aws.thecloudgarage.com:5000/register',
					method: 'POST',
					json: true,
					body: postvals
				};
		                  var register = request.post(options, function(err, resp, body) {
                                        console.log("logged_in cookie: ");
                                        });
		res.redirect('/');
            }
        });
    }
});

   module.exports = app;

}());

