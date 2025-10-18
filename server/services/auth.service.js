const bcrypt = require("bcrypt");
const userModel = require("../models/user.model");
const mailService = require("./mail.service");
const tokenService = require("./token.service");
const deviceModel = require("../models/device.model");
const UserDto = require("../dtos/user.dto");
const DeviceDto = require("../dtos/device.dto");
const BaseError = require("../errors/base.error");
const messageModel = require("../models/message.model");
const tokenModel = require("../models/token.model");

class AuthService {
  async login(email) {
    await mailService.sendOtp(email);
    return { email };
  }

  async createSession(userId, req) {
    const sessions = await deviceModel.find({ user: userId });

    if (sessions.length >= 3) {
      const oldSession = await deviceModel
        .findOne({ user: userId })
        .sort({ lastUsedAt: 1 });
      if (oldSession) await deviceModel.findByIdAndDelete(oldSession._id);
    }

    const newSession = await deviceModel.create({
      user: userId,
      deviceName: req.headers["user-agent"],
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
    });
    const user = await userModel.findById(userId);
    const userDto = new UserDto(user);
    const deviceDto = new DeviceDto(newSession);
    const tokens = tokenService.generateToken(userDto.id, deviceDto.id);
    await tokenService.saveToken(deviceDto.id, tokens.refreshToken);
    return { user: userDto, device: deviceDto, ...tokens };
  }

  async verify(email, otp, req) {
    const result = await mailService.verifyOtp(email, otp);
    if (!result) {
      throw BaseError.BadRequest("Invalid OTP");
    }

    let user = await userModel.findOne({ email });
    if (!user) {
      user = await userModel.create({ email, isVerified: true });
    } else {
      user.isVerified = true;
      await user.save();
    }
    if (user.twoFactorEnabled) {
      return { message: "Otp verified" };
    }
    const data = await this.createSession(user._id, req);
    return data;
  }

  async verify2FA(email, password, req) {
    const user = await userModel.findOne({ email });
    if (!user) throw BaseError.BadRequest("Bad authorization");

    const isValid = await bcrypt.compare(password, user.twoFactorSecret);
    if (!isValid) throw BaseError.BadRequest("Password is incorrect");

    const data = await this.createSession(user._id, req);
    return data;
  }

  async refresh(refreshToken) {
    if (!refreshToken) {
      throw BaseError.Unauthorized();
    }
    const payload = tokenService.validateRefreshToken(refreshToken);
    if (!payload) throw BaseError.Unauthorized();
    const tokenDb = await tokenService.findToken(
      refreshToken,
      payload.deviceId
    );
    if (!tokenDb) throw BaseError.Unauthorized();
    const currentSession = await deviceModel.findOne({
      user: payload.userId,
      _id: payload.deviceId,
    });

    if (!currentSession) throw BaseError.Unauthorized();
    const user = await userModel.findOne({ _id: currentSession.user });
    if (!user) throw BaseError.BadRequest("User not found");

    const deviceDto = new DeviceDto(currentSession);
    const userDto = new UserDto(user);

    // If the provided token equals the previousRefreshToken, only allow within grace window
    const usingPrevious =
      tokenDb.previousRefreshToken &&
      tokenDb.previousRefreshToken === refreshToken;

    if (usingPrevious && !tokenService.isPreviousTokenValid(tokenDb)) {
      throw BaseError.Unauthorized();
    }

    // If using previous token within grace window, avoid rotating again to prevent cookie race
    if (usingPrevious) {
      const { accessToken, refreshToken: newRefreshToken } =
        tokenService.generateToken(userDto.id, deviceDto.id);
      // Do not rotate refresh token again; use the current stored refresh token
      return {
        user: userDto,
        device: deviceDto,
        accessToken,
        refreshToken: tokenDb.refreshToken || newRefreshToken,
      };
    }

    // Normal path: rotate refresh token
    const tokens = tokenService.generateToken(userDto.id, deviceDto.id);
    await tokenService.saveToken(deviceDto.id, tokens.refreshToken);
    return { user: userDto, device: deviceDto, ...tokens };
  }

  async logoutOne(deviceId, userId) {
    await tokenModel.findOneAndDelete({ device: deviceId });
    await deviceModel.findByIdAndDelete(deviceId);
  }

  async logoutAll(userId) {
    await deviceModel.deleteMany({ user: userId });
  }

  async logout(userId, deviceId) {
    await deviceModel.findOneAndDelete({ user: userId, _id: deviceId });
  }
}

module.exports = new AuthService();
