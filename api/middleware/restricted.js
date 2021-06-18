const { JWT_SECRET } = require("../secrets/secret");
const jwt = require("jsonwebtoken");
const User = require("../auth/auth-model");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    res.status(401).json({ message: "token required" });
  } else {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        res.status(401).json({ message: "token invalid" });
      } else {
        req.decodedJwt = decoded;
        next();
      }
    });
  }
};
/*
    IMPLEMENT

    1- On valid token in the Authorization header, call next.

    2- On missing token in the Authorization header,
      the response body should include a string exactly as follows: "token required".

    3- On invalid or expired token in the Authorization header,
      the response body should include a string exactly as follows: "token invalid".
  */

const checkPayload = (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    next({
      status: 401,
      message: "username and password required",
    });
  } else {
    next();
  }
};

const checkUniqueName = async (req, res, next) => {
  const { username } = req.body;
  const existingName = await User.findBy({ username });

  if (existingName.length) {
    next({
      status: 422,
      message: "username taken",
    });
  } else {
    next();
  }
};

module.exports = {
  restricted,
  checkUniqueName,
  checkPayload,
};
