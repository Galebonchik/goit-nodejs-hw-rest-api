const express = require("express");

const router = express.Router();

const {
  getAllContacts,
   getContactById,
  addContact,
  updateContact,
  updateStatusContact,
  deleteContact,
} = require("../../controllers/contacts-controller");

const { schemas } = require("../../models/contact");
const { validateBody, isValidId, authenticate } = require("../../middlewares");

router.get("/", authenticate, getAllContacts);
router.get("/:contactId", authenticate, isValidId, getContactById);
router.post("/", authenticate, validateBody(schemas.addShema), addContact);
router.put(
  "/:contactId",
  isValidId,
  validateBody(schemas.addShema),
  updateContact
);
router.patch(
  "/:contactId/favorite",
  isValidId,
  validateBody(schemas.updateFavoriteSchema),
  updateStatusContact
);
router.delete("/:contactId", authenticate, isValidId, deleteContact);

module.exports = router;
