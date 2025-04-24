import jwt, { JwtPayload } from "jsonwebtoken";
import { Request, Response, NextFunction} from "express";
import prisma from "../db/prisma.js";
import express from "express";

interface DecodedToken extends JwtPayload {
  userId: string;
}

declare global {
  namespace Express {
    export interface Request {
      user: {
        id: string;
      };
    }
  }
}

const protectRoute = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      res.status(401).json({ error: "Not authorized, no token" });
      return;
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as DecodedToken;

    const user = await prisma.user.findUnique({ where: { id: decoded.userId } });

    if (!user) {
      res.status(401).json({ error: "Not authorized, user not found" });
      return;
    }

    // Attach user information to the request object
    req.user = { id: user.id };

    // Pass control to the next middleware or route handler
    next();
  } catch (error) {
   res.status(401).json({ error: "Not authorized, token failed" });
   return;
  }
};

export default protectRoute;