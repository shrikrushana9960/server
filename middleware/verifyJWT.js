const jwt = require("jsonwebtoken");
const authConfig = require("../config/auth.config");

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  // Check if Authorization header exists and starts with 'Bearer '
  if (!req?.cookies?.access_token) {
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ success: false, message: "Unauthorized: No token provided" });
    }
  }

  // Extract the token from the Authorization header
  let token = authHeader.split(" ")[1] || req.cookies.access_token;

  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "Unauthorized: No token provided" });
  }

  jwt.verify(token, authConfig.secret, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .json({ success: false, message: "Unauthorized: Invalid token" });
    }

    req.user = decoded;
    next();
  });
};

module.exports = verifyJWT;
