const express = require('express')
const app = express()
require('dotenv').config()
var bodyParser = require('body-parser')
const mongoose = require("mongoose");
const http = require("http");
const cors = require("cors");
const logger = require("morgan");
const cookieParser = require('cookie-parser');
const errorHandler = require('./middleware/errorMiddlware')
const { dbConnect } = require("./config/dbConfig");
const userRoute = require("./routes/user.routes");


app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(logger("dev"));
app.use(cookieParser())
const corsOptions = {
  origin: 'http://localhost:3000',
  credentials: true,
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));

dbConnect();
app.use("/api/v1/user", userRoute);

app.get("/", function (req, res) {
  try {
    res.json({
      message: "Server is running",
      time:new Date(),
      database: mongoose.connection.readyState === 1 ? "Connected" : "Not Connected",
    });
  } catch (e) {
    console.log(e);
  }
});
app.all("*", (req, res, next) => {
  const err = new Error(`Can't find ${req.originalUrl} on the server !`);
  err.status = 404;
  next(err);

})
app.use(
  errorHandler
);
app.listen(process.env.PORT, () => {
  console.log(`Example app listening on port ${process.env.PORT}`)
})