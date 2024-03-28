const express = require("express");
const { signin, signup, allUsers, getUser } = require("../controller/userController");
const verifyJWT = require("../middleware/verifyJWT");

const router = express.Router();

router.post("/login", signin);
router.get("/",verifyJWT,getUser);
router.post("/", signup);
router.get("/allUsers",verifyJWT, allUsers)
module.exports = router;
