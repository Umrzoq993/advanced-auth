const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const deviceModel = require("../models/device.model");
const tokenModel = require("../models/token.model");

class TokenService {
  generateToken(userId, deviceId) {
    const accessToken = jwt.sign(
      { userId, deviceId },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: "15m",
      }
    );
    const refreshToken = jwt.sign(
      { userId, deviceId },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "30d" }
    );

    return { accessToken, refreshToken };
  }

  generateAccessToken(userId) {
    try {
      const accessToken = jwt.sign(
        { userId },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "5m" }
      );
      return { accessToken };
    } catch (error) {
      return null;
    }
  }

  async findToken(refreshToken, deviceId) {
    // Try to match current token first, then allow a brief grace period for previousRefreshToken
    return await tokenModel.findOne({
      device: deviceId,
      $or: [{ refreshToken }, { previousRefreshToken: refreshToken }],
    });
  }

  async deleteToken(refreshToken) {
    return await tokenModel.findOneAndDelete({ refreshToken });
  }

  async saveToken(deviceId, refreshToken) {
    const existToken = await tokenModel.findOne({ device: deviceId });

    if (existToken) {
      // Keep the last token in previousRefreshToken to handle concurrent rotations
      existToken.previousRefreshToken = existToken.refreshToken;
      existToken.refreshToken = refreshToken;
      existToken.rotatedAt = new Date();
      return existToken.save();
    }
    const token = await tokenModel.create({ device: deviceId, refreshToken });
    return token;
  }

  // Optional cleanup helper to invalidate any previous token older than a small window
  isPreviousTokenValid(tokenDoc, windowMs = 15000) {
    if (!tokenDoc?.previousRefreshToken || !tokenDoc?.rotatedAt) return false;
    const age = Date.now() - new Date(tokenDoc.rotatedAt).getTime();
    return age <= windowMs;
  }

  validateRefreshToken(refreshToken) {
    try {
      const payload = jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET
      );
      return payload;
    } catch (error) {
      return null;
    }
  }

  validateAccessToken(token) {
    try {
      return jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    } catch (error) {
      return null;
    }
  }
}

module.exports = new TokenService();
