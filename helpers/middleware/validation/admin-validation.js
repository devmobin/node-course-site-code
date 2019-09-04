const { body } = require("express-validator/check");

exports.addProduct = [
  body("title")
    .isString()
    .isLength({ min: 3 })
    .trim(),
  body("price").isFloat(),
  body("description")
    .isLength({ min: 5, max: 400 })
    .trim()
];

exports.editProduct = [
  body("title")
    .isString()
    .isLength({ min: 3 })
    .trim(),
  body("price").isFloat(),
  body("description")
    .isLength({ min: 5, max: 400 })
    .trim()
];
