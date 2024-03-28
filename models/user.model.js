const mongoose = require("mongoose");
const userModel = new mongoose.Schema(
  {
    name: {
      type: String
    },
    dob: Date,
    email: {
      type: String,
      unique: true,
    },
    password: String,
  },
  {
    timestamps: true,
  },
  { strict: false }
);

const User = mongoose.model("users", userModel);
module.exports = User;
