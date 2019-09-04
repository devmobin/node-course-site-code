const express = require("express");

const authController = require("../controllers/auth");
const authValidation = require("../helpers/middleware/validation/auth-validation");

const router = express.Router();

router.get("/login", authController.getLogin);

router.post("/login", authValidation.login, authController.postLogin);

router.get("/signup", authController.getSignup);

router.post("/signup", authValidation.signup, authController.postSignup);

router.post("/logout", authController.postLogout);

router.get("/reset", authController.getReset);

router.post("/reset", authController.postReset);

router.get("/reset/:token", authController.getNewPassword);

router.post("/new-password", authController.postNewPassword);

module.exports = router;
