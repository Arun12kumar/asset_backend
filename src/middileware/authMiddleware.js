import jwt from "jsonwebtoken";
import { promisify } from "util";
import sessionModel from "../models/sessionModel.js";

const verifyToken = promisify(jwt.verify);

const getCookieOptions = () => {
  const isProduction = process.env.NODE_ENV === "production";
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "strict",
    path: "/",
  };
};

export const authMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies?.accessToken;
    if (!token) {
      return res.status(401).json({ success: false, message: "No token provided" });
    }

    // ✅ Step 1: Verify JWT asynchronously
    let decoded;
    try {
      decoded = await verifyToken(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ success: false, message: "Invalid or expired token" });
    }

    // ✅ Step 2: Fetch session from DB directly (Redis removed)
    const session = await sessionModel
      .findOne({ tokenId: decoded.jti, valid: true })
      .select("_id userId valid createdAt updatedAt");

    if (!session) {
      // Clear cookies on invalid session
      res.clearCookie("accessToken", getCookieOptions());
      res.clearCookie("refreshToken", getCookieOptions());
      return res.status(403).json({ success: false, message: "Session is invalid or logged out" });
    }

    // ✅ Step 3: Attach user and session to request
    req.user = decoded;
    req.session = session;

    // Continue to next middleware / route
    next();

  } catch (error) {
    console.error("authMiddleware error:", error);
    res.status(500).json({ success: false, message: "Server Error: " + error.message });
  }
};
