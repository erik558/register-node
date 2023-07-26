import express from "express";
import session from "express-session";
import path from "path";
import bcrypt from 'bcrypt';
import passport from "passport";
import passportLocal from "passport-local";


let users = []

const app = express();

app.use(session({
    secret: process.env.SESION_SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(express.urlencoded({ extended: true }))

app.use(passport.initialize());
app.use(passport.session());
passport.use(new passportLocal.Strategy({
    usernameField: "email"
}, async (email, password, done) => {
    const user = users.find((user) => user.email === email)

    if (user === undefined) {
        return done(null, null, { message: "Incorrect email" });
    }

    if (await bcrypt.compare(password, user.password)) {
        return done(null, user);
    }


    done(null, null, { message: "Incorrent password" })
}))

passport.serializeUser((user, done) => {
    done(null, user.id);
});
passport.deserializeUser((id, done) => {
    done(null, users.find((user) => user.id === id));
});

app.get("/register", checkNotAuthenticetion, (req, res) => {
    res.sendFile(path.resolve("views/register.html"))
})

app.post("/login", passport.authenticate("local", {
    failureRedirect: "/login",
    successRedirect: "/",
}));

app.post("/register", async (req, res) => {

    const { name, email, password } = req.body
    const hashedpwd = await bcrypt.hash(password, 10)
    users.push({
        id: `${Date.now()}_${Math.random()}`,
        name,
        email,
        password: hashedpwd
    })
    res.redirect('/login')
});

app.get("/login", checkNotAuthenticetion, (req, res) => {
    res.sendFile(path.resolve("views/login.html"))
})

app.get("/", checkAuthenticetion, (req, res) => {

    res.sendFile(path.resolve("views/app.html"))
})

app.get('/logout', (req, res) => {

    req.logout((err) => {
        if (err) {
            console.error('Error during logout:', err);
            return res.status(500).send('Error during logout');
        }
        res.redirect('/');
    });
});


function checkAuthenticetion(req, res, next) {
    if (req.isAuthenticated() === false) {
        res.redirect("/login")
    }
    next()
}

function checkNotAuthenticetion(req, res, next) {
    if (req.isAuthenticated() === true) {
        res.redirect("/")
    }
    next()
}


app.listen(process.env.PORT)