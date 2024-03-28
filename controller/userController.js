const config = require("../config/auth.config");

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");
const User = require("../models/user.model");
const validator = require("./errorsSender");

exports.signup = async (req, res, next) => {
  try {
    const validation = validator(["name", "dob", "email", "password"], req);

    if (validation.length) {
      const err = new Error(`Missing ${validation}`);
      err.status = 400;
      return next(err);
    }

    const user = {
      name: req.body.name,
      email: req.body.email,
      dob: req.body.dob,
      password: bcrypt.hashSync(req.body.password, 8),
    };

    let data = await User.create(user);
    if (data) {
      const token = jwt.sign({ id: user.id }, config.secret, {
        algorithm: "HS256",
        expiresIn: 2 * 24 * 60 * 60,
      });

      res
        .cookie("access_token", token, {
          httpOnly: true,
          maxAge: 2 * 24 * 60 * 60 * 1000,
        })
        .status(200)
        .json({ success: true, data,token });
    }
  } catch (e) {
    console.log(e);
    const err = new Error(`Internal Server Error ` + e);
    err.status = 200;
    return next(err);
  }
};
exports.signin = async (req, res, next) => {
  const validation = validator(["email", "password"], req, res, next);

  if (!validation.length == 0) {
    const err = new Error(`Missing ${validation}`);
    err.status = 400;
    return next(err);
  }

  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      const err = new Error("User not found.");
      err.status = 404;
      return next(err);
    }

    const passwordIsValid = bcrypt.compareSync(
      req.body.password,
      user.password
    );

    if (!passwordIsValid) {
      return res
        .status(401)
        .json({ accessToken: null, message: "Invalid Password!" });
    }

    const token = jwt.sign({ id: user.id }, config.secret, {
      algorithm: "HS256",
      expiresIn: 2 * 24 * 60 * 60,
    });

    res
      .cookie("access_token", token, {
        httpOnly: true,
        maxAge: 2 * 24 * 60 * 60 * 1000,
      })
      .status(200)
      .json({
        success: true,
        data: {
          id: user._id,
          name: user.name,
          email: user.email,
        },
        token
      });
  } catch (e) {
    console.log(e);
    const err = new Error(`Internal Server Error`);
    err.status = 500;
    return next(err);
  }
};
exports.getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id, { name: 1, email: 1 });
    if (!user) {
      const err = new Error("User not found.");
      err.status = 404;
      return next(err);
    }
    res.status(200).json({
      success: true,
      data: user,
    });
  } catch (e) {
    console.log(e);
    const err = new Error(`Internal Server Error`);
    err.status = 500;
    return next(err);
  }
};
exports.allUsers = async (req, res, next) => {
  try {
    const users = await User.find({ ...req.query });
    res.status(200).json({
      success: true,
      data: users,
    });
  } catch (e) {
    console.log(e);
    const err = new Error(`Internal Server Error`);
    err.status = 500;
    return next(err);
  }
};
