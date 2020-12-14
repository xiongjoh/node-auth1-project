const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require('bcryptjs')
const session = require("express-session");

const Auth = require("./auth-model");

// middleware
const checkUser = (req, res, next) => {
  if (!req.body.username || !req.body.password) {
    res.status(401).json("bad payload");
  } else {
    next();
  }
};
const checkUsernameUnique = async (req, res, next) => {
  try {
    const rows = await Auth.findBy({ username: req.body.username });
    if (!rows.length) {
      next();
    } else {
      res.status(401).json("invalid username");
    }
  } catch (err) {
    res.status(500).json({message:err.message});
  }
};

const checkUsernameExists = async (req, res, next) => {
    try {
      const rows = await Auth.findBy({ username: req.body.username })
      if (rows.length) {
        req.userData = rows[0]
        next()
      } else {
        res.status(401).json('user does not exist')
      }
    } catch (err) {
      res.status(500).json({message:err.message})
    }
  }


const KnexSessionStore = require("connect-session-knex")(session);

const server = express();

const config = {
  name: "sessionId",
  secret: "keept it secret, keeep it safe!",
  cookie: {
    maxAge: 1000 * 60 * 60,
    secure: false,
    httpOnly: true,
  },
  resave: false,
  saveUninitialized: false,
  store: new KnexSessionStore({
    knex: require("../database/connection.js"),
    tablename: "sessions",
    sidfieldname: "sid",
    createtable: true,
    clearInterval: 1000 * 60 * 60,
  }),
};

server.use(session(config));
server.use(helmet());
server.use(express.json());
server.use(cors());

server.post("/api/register", checkUser, checkUsernameUnique, async (req, res) => {
  try {
    const hash = bcrypt.hashSync(req.body.password, 12);
    const user = await Auth.add({
      username: req.body.username,
      password: hash,
    });
    res.status(201).json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
server.post("/api/login", checkUser, checkUsernameExists, async (req, res) => {
  try {
    const verifies = bcrypt.compareSync(
      req.body.password,
      req.userData.password
    );
    if (verifies) {
        // set user and userId
      req.session.user = req.userData;
      req.session.userId = req.userData.id;
      res.json({message:`Logged In`});
    } else {
        res.status(401).json('you shall not pass!')
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
server.get("/api/users", async (req, res) => {
  try {
    if (req.session && req.session.user) {
      console.log(req.session);
      const users = await Auth.find();
      res.status(200).json(users);
    } else {
      res.json(`You shall not pass!`);
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
server.get('/api/logout', (req, res) => {
    if(req.session) {
        req.session.destroy(err => {
            if(err) {
                res.json('unable to leave session')
            }
            else {
                res.json('logged out')
            }
        })
    } else {
        res.json('there was no session')
    }
})

server.get("/", (req, res) => {
  res.json({ api: "up" });
});

module.exports = server;
