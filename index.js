const express = require('express');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const saml = require('passport-saml').Strategy;
const app = express()
const port = process.env.PORT || 3000;

let userProfile;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET }));

app.use(passport.initialize());
app.use(passport.session());

const findByEmail = function (email, profile, callback) {
  return callback(null, {
    user_id: profile.ad_guid,
    email: profile.email,
	name: profile.name
  });
}

passport.use(new saml(
  {
    path: '/saml/consume',
    entryPoint: process.env.SSO_ENTRYPOINT,
    issuer: process.env.SSO_ISSUER,
    cert: process.env.SSO_CERT,
    protocol: "http://",
    logoutUrl: process.env.SSO_SIGNOUT_URL,
  },
  function(profile, done) {
    userProfile = profile;
    findByEmail(profile.email, profile, function(err, user) {
      if (err) {
        return done(err);
      }
      return done(null, user);
    });
  })
);

passport.serializeUser((user, done) => {
	done(null, user);
});

passport.deserializeUser((user, done) => {
	done(null, user);
});

const redirectToLogin = (req, res, next) => {
	if (!req.isAuthenticated() || req.user == null) {
		return res.redirect('/login');
	}
	next();
};


app.get('/', redirectToLogin, (req, res) => {
	res.send(`Logged In<br/>Welcome ${req.user.email}<br/>${JSON.stringify(req.user)}`);
});

app.get(
	'/login',
	passport.authenticate('saml', {
		successRedirect: '/',
		failureRedirect: '/login'
	})
);

app.get('/failed', (req, res) => {
	res.status(401).send('Login failed');
});
app.post('/home', (req, res) => {
	res.send('Hello World!')
});

app.get('/logout', (req, res) => {
	if (req.user == null) {
		return res.redirect('/home');
	}

	return strategy.logout(req, (err, uri) => {
		req.logout();

		userProfile = null;
		return res.redirect(uri);
	});
});

app.post(
	'/saml/consume',
	passport.authenticate('saml', {
		failureRedirect: '/failed',
		failureFlash: true
	}),
	(req, res) => {

		// saml assertion extraction from saml response
		// var samlResponse = res.req.body.SAMLResponse;
		// var decoded = base64decode(samlResponse);
		// var assertion =
		// 	('<saml2:Assertion' + decoded.split('<saml2:Assertion')[1]).split(
		// 		'</saml2:Assertion>'
		// 	)[0] + '</saml2:Assertion>';
		// var urlEncoded = base64url(assertion);

		// success redirection to /app
		return res.redirect('/');
	}
);

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})