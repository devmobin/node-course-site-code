const express = require("express");

const adminController = require("../controllers/admin");
const adminValidation = require("../helpers/middleware/validation/admin-validation");
const isAuth = require("../helpers/middleware/Authentication/is-auth");

const router = express.Router();

router.get("/products", isAuth, adminController.getProducts);

router.get("/add-product", isAuth, adminController.getAddProduct);

router.post(
  "/add-product",
  adminValidation.addProduct,
  isAuth,
  adminController.postAddProduct
);

router.get("/edit-product/:productId", isAuth, adminController.getEditProduct);

router.post(
  "/edit-product",
  adminValidation.editProduct,
  isAuth,
  adminController.postEditProduct
);

router.delete("/product/:productId", isAuth, adminController.deleteProduct);

module.exports = router;
