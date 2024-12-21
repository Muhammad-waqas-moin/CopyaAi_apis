require("dotenv").config();
const jwt = require("jsonwebtoken");
const { log } = require("mercedlogger");

const isLoggedIn = async (req, res, next) => {
  try {
    if (req.headers.authorization) {
      const token = req.headers.authorization.split("")[1];
      if (token) {
        try {
          const payload = jwt.verify(token, process.env.SECRET);
          req.user = payload;
          return next();
        } catch (error) {
          console.error("Token error ==>", error);
          return res.status(401).json({
            success: false,
            messgae: "Token verification failed",
          });
        }
      } else {
        return res.status(400).json({
          message: "Malformed auth header",
          success: false,
        });
      }
    } else {
      return res.status(401).json({
        message: "No authorization header",
        success: false,
      });
    }
  } catch (error) {
    log.error("error :", error);
    res.status(500).json({
      message: "something went wrong",
      status: false,
      error: error,
    });
  }
};

const authorizationRole = (...allowedRoles) => {
  return (req, res, next) => {
    try {
      if (!req.user || !allowedRoles.includes(req.user.role)) {
        return res.status(403).json({
          message: `Access restricted to roles: ${allowedRoles.join(", ")}`,
        });
      }
      next();
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "Authorization failed",
        error: error.message,
      });
    }
  };
};

module.exports = { isLoggedIn, authorizationRole };
