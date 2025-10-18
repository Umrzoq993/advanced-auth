const BaseError = require("../errors/base.error");
const deviceModel = require("../models/device.model");
const userModel = require("../models/user.model");
const tokenService = require("../services/token.service");

module.exports = async function (req, res, next) {
  try {
    const authorization = req.headers.authorization;
    if (!authorization) throw BaseError.Unauthorized();

    const parts = authorization.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer")
      throw BaseError.Unauthorized();

    const token = parts[1];

    const payload = tokenService.validateAccessToken(token);
    if (!payload) throw BaseError.Unauthorized();

    const user = await userModel.findById(payload.userId);
    const device = await deviceModel.findById(payload.deviceId);
    if (!user || !device) throw BaseError.Unauthorized();

    req.user = user;
    req.device = device;

    next();
  } catch (error) {
    next(error);
  }
};
