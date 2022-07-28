const express = require("express");
const router = express.Router();

const userController = require("../controller/userController");
const evntController = require("../controller/eventController");
const { authorization } = require("../middleware/mid");

// User`s Api`s
router.post("/registerUser", userController.register);
router.post("/login", userController.login);
router.get("/logout", authorization, userController.logout);
router.patch("/changePassword/:userId", authorization, userController.passwordChange);

// Event`s Api`s
router.post("/addEvent", evntController.addsEvent);
router.post("/inviteEvent/:id", evntController.invites);
router.get("/listEvent", evntController.eventssss);
router.patch("/changeEvent/:id", evntController.updateEventss);
router.get("/eventsDetails/:id", evntController.detailssss);

module.exports = router;