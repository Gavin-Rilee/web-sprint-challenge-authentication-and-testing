const router = require("express").Router();
const {
  restricted,
  checkPayload,
  checkUniqueName,
} = require("../middleware/restricted");

const { tokenBuilder } = require("../secrets/tokenBuilder");
const { JWT_SECRET } = require("../secrets/secret");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Users = require("../auth/auth-model");

router.post("/register", checkPayload, checkUniqueName, (req, res, next) => {
  const user = req.body;
  const rounds = process.env.BCRYPT_ROUNDS || 8;
  const hash = bcrypt.hashSync(user.password, rounds);
  user.password = hash;
  Users.add(req.body)
    .then((user) => {
      res.status(201).json(user);
    })
    .catch((err) => {
      next(err);
    });
});

router.post("/login", checkPayload, (req, res, next) => {
  const { username, password } = req.body;

  Users.findBy({ username })
    .then(([existing]) => {
      if (existing && bcrypt.compareSync(password, existing.password)) {
        const token = tokenBuilder(existing);
        res.status(200).json({
          message: `Welcome, ${existing.username}`,
          token: token,
        });
      } else {
        next({
          status: 401,
          message: "invalid credentials",
        });
      }
    })
    .catch((err) => {
      next(err);
    });
});

module.exports = router;
