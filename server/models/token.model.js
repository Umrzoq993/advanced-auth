const { Schema, model } = require("mongoose");

const tokenSchema = new Schema({
  device: { type: Schema.Types.ObjectId, ref: "DeviceModel" },
  refreshToken: { type: String, required: true },
  // To tolerate brief concurrent refresh requests, keep the previous token for a short window
  previousRefreshToken: { type: String, default: null },
  rotatedAt: { type: Date, default: null },
});

module.exports = model("TokenModel", tokenSchema);
