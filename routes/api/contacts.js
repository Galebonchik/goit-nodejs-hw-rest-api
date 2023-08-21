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

const { shemas } = require("../../models/contact");
const { validateBody, isValidId } = require("../../middlewares");

router.get("/", getAllContacts);
router.get("/:contactId", isValidId, getContactById);
router.post("/", validateBody(shemas.addShema), addContact);
router.put(
  "/:contactId",
  isValidId,
  validateBody(shemas.addShema),
  updateContact
);
router.patch(
  "/:contactId/favorite",
  isValidId,
  validateBody(shemas.updateFavoriteSchema),
  updateStatusContact
);
router.delete("/:contactId", isValidId, deleteContact);

module.exports = router;
