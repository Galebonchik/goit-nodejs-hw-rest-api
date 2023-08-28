const express = require("express");

const {
  register,
  login,
  getCurrent,
  logout,
  updateSubscription,
} = require("../../controllers/auth-controller");
const { validateBody, authenticate } = require("../../middlewares");
const { schemas } = require("../../models/user");

const router = express.Router();

router.post("/register", validateBody(schemas.registerSchema), register);
router.post("/login", validateBody(schemas.loginSchema), login);
router.get("/current", authenticate, getCurrent);
router.post("/logout", authenticate, logout);
router.patch(
  "/",
  authenticate,
  validateBody(schemas.subscriptionSchema),
  updateSubscription
);
module.exports = router;