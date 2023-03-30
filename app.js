//jshint esversion:6
require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// var encrypt = require('mongoose-encryption');   level 1
// const md5 = require('md5')   level 2
// level 3 start
// const bcrypt = require('bcrypt');   
// const saltRounds = 10;    
//level 4 start
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const  findOrCreate = require('mongoose-findorcreate')

const app = express();


app.use(express.static('public'))
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}))
app.use(session({
    secret: 'mySessionSecret.',
    resave: false, // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
  }))
app.use(passport.initialize()); //used middleware 
app.use(passport.session());   //used express session() with passport 


//DB
mongoose.connect(process.env.DB_URL);

//Schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    userDisplayName: String,
    googleId: String,
    githubId: String,
    secret: String

})

userSchema.plugin(passportLocalMongoose);   //passportLocalMongoose used as plugin //level 4
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, { secret: process.env.KEY, encryptedFields: ['password'] });  //level 1 security

//model
const User = new mongoose.model('User', userSchema);



/*
passport-local-mongoose adds a helper method createStrategy as static method to your schema. 
Strategy {
  _usernameField: 'username',
  _passwordField: 'password',
  name: 'local',
  _verify: [Function (anonymous)],
  _passReqToCallback: undefined
}

*/
//level 4
passport.use(User.createStrategy()); 
//serializeUser  and deserializeUser for maintaining sessions
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });


//setting up googleStrategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);  //client-user profile
    User.findOrCreate({ googleId: profile.id , userDisplayName: profile.displayName}, function (err, user) {
      return cb(err, user);
    });
  }
));

//setting up Github Strategy 
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    //console.log(profile);  //client-user profile
    User.findOrCreate({ githubId: profile.id, userDisplayName: profile.displayName }, function (err, user) {
      return done(err, user);
    });
  }
));


app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));


app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }));

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


app.get('/', (req, res)=>{
    res.render('home');
});


app.get('/register', (req, res)=>{
    res.render('register');
});


app.get('/secrets', (req, res)=>{
    User.find({secret: {$ne: null}})
    .then((result)=>{
        res.render('secrets', {"Allsecrets": result});
    })
    .catch((err) => console.log(err))
});

app.get('/submit' , (req, res)=>{
    if(req.isAuthenticated()){
        res.render('submit')
    }
    else{
        res.redirect('/login');
    }
    
})

app.post('/submit', (req, res)=>{
    if(req.isAuthenticated()){   //passport added these methods like logIn , logOut, is Authentictaed
        const newSecret = req.body.secret;
        User.findById(req.session.passport.user.id)
        .then((founduser)=>{
            founduser.secret = newSecret;
            founduser.save()
                .then(()=>res.redirect('/secrets'))
                .catch((err)=>console.log(err))
        })
        .catch((err)=>console.log(err))

    }
    else{
        res.redirect('/login');
    }
})


app.get('/login', (req, res)=>{
    res.render('login');
})


app.get('/logout', (req, res)=>{
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
})

/*
Session always stored on the server.
If you want to see stored session value use echo $_SESSION['value']; in your script.
If you would like to check values of store data accessible use cookies.
 */
//https://medium.com/@alysachan830/cookie-and-session-ii-how-session-works-in-express-session-7e08d102deb8

app.get('/sessionTest', (req, res)=>{
    if (req.session.views) {
        req.session.views++
        res.setHeader('Content-Type', 'text/html')
        res.write('<p>views: ' + req.session.views + '</p>')
        res.write('<p>expires in: ' + (req.session.cookie.maxAge / 1000) + 's</p>')
        console.log(req.session);
        res.end()
      } else {
        req.session.views = 1
        req.session.hey = "ayush"
        res.end('welcome to the session demo. refresh!')
      }
})


app.post('/register', (req, res)=>{
    /*  
        const newUser = new User({
            email: req.body.username,
            password: md5(req.body.password) //hashed using md5 //level 2 security
        })
     

    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        // Store hash in your password DB.
        const newUser = new User({
            email: req.body.username,
            password: hash  //level 3 bcrypt with salting
        })
    
        newUser.save()
        .then(()=> res.render('secrets'))
        .catch(err => console.log(err))
    });
*/

    // hashing and salting and authentiacation using passport level 4
    //using passport-local-mongoose to register user without having saving the user to db (pas-loc-mog as a middleman to resgister and authenticate)

    User.register({username: req.body.username}, req.body.password, (err, user)=>{
        if(err){
            console.log(err);
            res.redirect('/register')
        }
        //when user successfully registered and authenticated we send a cookie to maintain the session 
        passport.authenticate('local')(req,res,()=>{    //then  authenticate the user and redirect
            res.redirect('/secrets')
        });
    });
});



app.post('/login', (req, res)=>{
/*
    // const psw = md5(req.body.password) //hashed using md5 //level 2 security

    const username = req.body.username
    const psw = req.body.password

    User.findOne({email: username})
    .then((founduser)=> {
        bcrypt.compare(psw, founduser.password, function(err, result) {    //level 3 security  bcrypt with salting
            if(result == true){
                res.render('secrets');
            }
            else{
                res.redirect('/')
            }
        });
    })
    .catch(err => console.log(err))
    
    */


    // hashing and salting and authentiacation using passport  level 4
    // using passport's login() 
    const user = new User({
        username: req.body.username,  // as per pass-loc-mong
        password: req.body.password
    })
//passport added these methods like logIn , logOut, is Authentictaed
    req.logIn(user, (err)=>{
        if (err){
            console.log(err);
            res.redirect('/login');
        } 
        else{
            //using local strategy and then a callback or authenticate(req, res, ());
            passport.authenticate('local',  { failureRedirect: '/login' })(req, res, ()=>{
                res.redirect('/secrets')
            })
        }
    })
})







app.listen(3000, ()=>{
    console.log('Server is listening');
})